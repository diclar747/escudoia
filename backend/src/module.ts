import { Module, Controller, Get, Post, Body, BadRequestException, UnauthorizedException, Headers, Injectable, OnModuleInit, OnModuleDestroy } from '@nestjs/common';
import { IsString, IsIn, MaxLength } from 'class-validator';
import { createHash } from 'node:crypto';
import { Pool } from 'pg';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

class UrlDto { @IsString() @MaxLength(2048) url!: string; }
class IndicatorDto { @IsString() @MaxLength(2048) indicator!: string; @IsIn(['url','phone']) category!: 'url'|'phone'; @IsIn(['malicious','suspicious']) verdict!: 'malicious'|'suspicious'; @IsString() @MaxLength(300) reason!: string; }
class PhoneDto { @IsString() @MaxLength(32) phone!: string; }
class ReportDto { @IsString() @MaxLength(2048) indicator!: string; @IsIn(['url','phone','sms','other']) category!: string; }

@Injectable()
class Db implements OnModuleInit, OnModuleDestroy {
 pool = new Pool({ connectionString: process.env.DATABASE_URL });
 async onModuleInit() {
  await this.pool.query(readFileSync(join(process.cwd(),'sql','001_init.sql'),'utf8'));
  await this.pool.query(readFileSync(join(process.cwd(),'sql','002_indicators.sql'),'utf8'));
 }
 async onModuleDestroy() { await this.pool.end(); }
}
function hashIndicator(value:string) { return createHash('sha256').update(value.trim().toLowerCase()).digest('hex'); }
function normalizePhone(value:string) { const v=value.replace(/[\s().-]/g,''); if(!/^\+?[0-9]{7,15}$/.test(v)) throw new BadRequestException('Número inválido'); return v; }
function normalizeUrl(input:string) { let u:URL; try {u=new URL(input.trim())}catch{throw new BadRequestException('URL inválida')}; if(!['http:','https:'].includes(u.protocol)||u.username||u.password) throw new BadRequestException('URL no permitida'); u.hash=''; return u.href; }
function analyzeUrl(input: string) {
 const url = new URL(normalizeUrl(input));
 const host = url.hostname.toLowerCase();
 const reasons: string[] = [];
 if (url.protocol === 'http:') reasons.push('La conexión no usa HTTPS');
 if (host.startsWith('xn--') || host.includes('.xn--')) reasons.push('Dominio internacionalizado: verificar posible suplantación');
 if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) reasons.push('La URL usa una dirección IP en lugar de un dominio');
 if (url.href.length > 300) reasons.push('URL inusualmente larga');
 const score = Math.min(100, reasons.length * 25);
 return { hostname:host, score, level:score>=50?'suspicious':score>0?'review':'unknown', reasons, disclaimer:'Ausencia de alertas NO significa que el enlace sea seguro.' };
}
@Controller()
class ApiController {
 constructor(private readonly db:Db) {}
 @Get('health') health(){ return {status:'ok',service:'escudo-ia',version:'0.2.1'}; }
 @Post('api/v1/analyze/url') async analyze(@Body() body:UrlDto){
  const heuristic=analyzeUrl(body.url);
  const canonical=normalizeUrl(body.url);
  const match=await this.db.pool.query('SELECT verdict,reason FROM threat_indicators WHERE indicator_hash=$1 AND category=$2',[hashIndicator(canonical),'url']);
  const verified=match.rows[0] || null;
  return {...heuristic, verdict:verified?.verdict || heuristic.level, verifiedReason:verified?.reason || null, source:verified?'curated_database':'heuristics', safe:false};
 }
 @Post('api/v1/analyze/phone') async phone(@Body() body:PhoneDto){
  const phone=normalizePhone(body.phone);
  const match=await this.db.pool.query('SELECT verdict,reason FROM threat_indicators WHERE indicator_hash=$1 AND category=$2',[hashIndicator(phone),'phone']);
  const verified=match.rows[0] || null;
  return {verdict:verified?.verdict || 'unknown',reason:verified?.reason || null,source:verified?'curated_database':'no_match',safe:false};
 }
 @Post('api/v1/admin/indicators') async addIndicator(@Headers('x-admin-key') key:string|undefined,@Body() body:IndicatorDto){
  if(!process.env.ADMIN_API_KEY || key!==process.env.ADMIN_API_KEY) throw new UnauthorizedException();
  const value=body.category==='url'?normalizeUrl(body.indicator):normalizePhone(body.indicator);
  await this.db.pool.query('INSERT INTO threat_indicators(indicator_hash,category,verdict,reason) VALUES($1,$2,$3,$4) ON CONFLICT(indicator_hash) DO UPDATE SET verdict=EXCLUDED.verdict,reason=EXCLUDED.reason,updated_at=NOW()', [hashIndicator(value),body.category,body.verdict,body.reason]);
  return {saved:true};
 }
 @Post('api/v1/reports') async report(@Body() body:ReportDto){
  await this.db.pool.query('INSERT INTO threat_reports(indicator_hash,category) VALUES($1,$2)',[hashIndicator(body.indicator),body.category]);
  return {received:true};
 }
}
@Module({controllers:[ApiController],providers:[Db]})
export class AppModule {}

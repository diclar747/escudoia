package py.com.cnid.escudoia
import android.app.role.RoleManager
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL

class MainActivity : ComponentActivity() {
 private var sharedText by mutableStateOf("")
 override fun onCreate(savedInstanceState: Bundle?) {
  super.onCreate(savedInstanceState)
  sharedText = if(intent?.action==Intent.ACTION_SEND) intent.getStringExtra(Intent.EXTRA_TEXT).orEmpty() else ""
  setContent { MaterialTheme { Dashboard(this,sharedText) } }
 }
 override fun onNewIntent(intent:Intent) { super.onNewIntent(intent); sharedText=intent.getStringExtra(Intent.EXTRA_TEXT).orEmpty() }
 fun requestScreeningRole() {
  if(Build.VERSION.SDK_INT>=29) {
   val rm=getSystemService(RoleManager::class.java)
   if(rm.isRoleAvailable(RoleManager.ROLE_CALL_SCREENING) && !rm.isRoleHeld(RoleManager.ROLE_CALL_SCREENING))
    startActivityForResult(rm.createRequestRoleIntent(RoleManager.ROLE_CALL_SCREENING),100)
  }
 }
}

@Composable
fun Dashboard(context:MainActivity, shared:String) {
 var url by remember(shared) { mutableStateOf(shared) }
 var result by remember { mutableStateOf("Sin análisis. Un resultado desconocido NO garantiza seguridad.") }
 var busy by remember { mutableStateOf(false) }
 var phone by remember { mutableStateOf("") }
 var numbers by remember { mutableStateOf(context.getSharedPreferences("escudo_local",Context.MODE_PRIVATE).getStringSet("silenced_numbers",emptySet()).orEmpty().toSet()) }
 val scope= rememberCoroutineScope()
 Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(20.dp),verticalArrangement=Arrangement.spacedBy(14.dp)) {
  Text("ESCUDO IA",style=MaterialTheme.typography.headlineLarge)
  Text("Protección antifraude · Versión 0.2.1",style=MaterialTheme.typography.titleMedium)
  Card { Text("Protección inicial: análisis de enlaces y silenciamiento local de números elegidos por vos. No leemos SMS ni conversaciones de WhatsApp.",Modifier.padding(16.dp)) }
  OutlinedTextField(url,{url=it},label={Text("URL o enlace compartido")},modifier=Modifier.fillMaxWidth())
  Button(enabled=!busy&&url.isNotBlank(),onClick={busy=true;scope.launch {result=try{request("api/v1/analyze/url","url",url)}catch(e:Exception){"No se pudo analizar: ${e.message}"};busy=false}}) { Text(if(busy) "Analizando…" else "Analizar enlace") }
  Text(result)
  HorizontalDivider()
  Text("Control local de llamadas",style=MaterialTheme.typography.titleLarge)
  Text("Los números añadidos se silencian cuando Android concede el rol de filtrado. No se bloquean ni rechazan llamadas.")
  OutlinedTextField(phone,{phone=it},label={Text("Número completo, ej. +595…")},modifier=Modifier.fillMaxWidth(),singleLine=true)
  Button(onClick={context.requestScreeningRole()}) {Text("Solicitar permiso de identificación de llamadas")}
  Row(horizontalArrangement=Arrangement.spacedBy(8.dp)) {
   Button(enabled=phone.matches(Regex("\\+?[0-9]{7,15}")),onClick={
    numbers=numbers+phone
    context.getSharedPreferences("escudo_local",Context.MODE_PRIVATE).edit().putStringSet("silenced_numbers",numbers).apply()
    phone=""
   }) {Text("Añadir")}
   OutlinedButton(onClick={numbers=emptySet();context.getSharedPreferences("escudo_local",Context.MODE_PRIVATE).edit().remove("silenced_numbers").apply()}) {Text("Vaciar lista")}
  }
  Text("Números silenciados: ${numbers.size}")
  numbers.sorted().forEach { Text("• $it") }
  HorizontalDivider()
  Text("Privacidad: el texto del enlace se envía a tu servidor HTTPS para analizarlo. Los números silenciados permanecen en este dispositivo.",style=MaterialTheme.typography.bodySmall)
 }
}

private suspend fun request(path:String,field:String,value:String):String=withContext(Dispatchers.IO) {
 val conn=URL(BuildConfig.API_BASE_URL+path).openConnection() as HttpURLConnection
 try {
  conn.requestMethod="POST";conn.connectTimeout=5000;conn.readTimeout=7000;conn.doOutput=true
  conn.setRequestProperty("Content-Type","application/json")
  conn.outputStream.use {it.write(JSONObject().put(field,value).toString().toByteArray(Charsets.UTF_8))}
  val status=conn.responseCode
  val stream=if(status in 200..299) conn.inputStream else conn.errorStream
  val response=stream?.bufferedReader()?.use{it.readText()}.orEmpty()
  if(status !in 200..299) "Error HTTP $status: $response" else {
   val j=JSONObject(response)
   val reasons=j.optJSONArray("reasons")
   val details=if(reasons==null) "" else (0 until reasons.length()).joinToString("; "){reasons.optString(it)}
   "Dominio: ${j.optString("hostname")}\nResultado: ${j.optString("verdict")}\nFuente: ${j.optString("source")}\n${j.optString("verifiedReason")} $details\nNo se garantiza que el enlace sea seguro."
  }
 } finally {conn.disconnect()}
}

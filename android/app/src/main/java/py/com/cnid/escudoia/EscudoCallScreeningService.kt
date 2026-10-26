package py.com.cnid.escudoia
import android.telecom.Call
import android.telecom.CallScreeningService
class EscudoCallScreeningService : CallScreeningService() {
 override fun onScreenCall(callDetails: Call.Details) {
  val number = callDetails.handle?.schemeSpecificPart.orEmpty().filter { it.isDigit() || it == '+' }
  val blocked = getSharedPreferences("escudo_local", MODE_PRIVATE).getStringSet("silenced_numbers", emptySet()).orEmpty()
  respondToCall(callDetails, CallResponse.Builder().setDisallowCall(false).setRejectCall(false).setSilenceCall(number.isNotBlank() && blocked.contains(number)).build())
 }
}

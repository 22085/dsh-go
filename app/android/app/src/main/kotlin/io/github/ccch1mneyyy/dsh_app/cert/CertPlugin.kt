package io.github.ccch1mneyyy.dsh_app.cert

import android.content.ContentValues
import android.content.Context
import android.os.Build
import android.os.Environment
import android.os.Handler
import android.os.Looper
import android.provider.MediaStore
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import java.io.File
import java.io.FileOutputStream
import kotlin.concurrent.thread

/**
 * Self-signed certificate generation for the app's own use, MethodChannel `dsh/cert`.
 *
 * - `generate {alias, password, cn, o, ou, l, st, c, years, keySize}` → a map with
 *   `{alias, filename, sha1, sha256, notAfter, keySize}`. The PKCS12 file is saved to
 *   the phone's Downloads folder as `<alias>.p12` (it can be renamed to `.keystore`);
 *   the SHA1/SHA256 fingerprints are what an app store's Android platform registration
 *   asks for. The key generation itself is the proven pure-Java [CertGen] (no BouncyCastle);
 *   the password is used only to protect the keystore and is never stored or logged.
 *
 * Nothing here reads user content, keys or tokens.
 */
class CertPlugin : FlutterPlugin, MethodChannel.MethodCallHandler {

    private var methods: MethodChannel? = null
    private lateinit var context: Context
    private val main = Handler(Looper.getMainLooper())

    override fun onAttachedToEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        context = binding.applicationContext
        methods = MethodChannel(binding.binaryMessenger, CHANNEL).also { it.setMethodCallHandler(this) }
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        methods?.setMethodCallHandler(null)
        methods = null
    }

    override fun onMethodCall(call: MethodCall, result: MethodChannel.Result) {
        when (call.method) {
            "generate" -> background(result) { generate(call) }
            else -> result.notImplemented()
        }
    }

    private fun background(result: MethodChannel.Result, work: () -> Any?) {
        thread(name = "dsh-cert") {
            val outcome = runCatching(work)
            main.post {
                outcome.fold(
                    onSuccess = { result.success(it) },
                    onFailure = { result.error("failed", it.message, null) },
                )
            }
        }
    }

    private fun generate(call: MethodCall): Map<String, Any?> {
        val rawAlias = call.argument<String>("alias") ?: ""
        val alias = rawAlias.replace(Regex("[^A-Za-z0-9._-]"), "_").trim().ifEmpty { "mykey" }
        val password = call.argument<String>("password") ?: ""
        require(password.length >= 6) { "password too short" }
        val years = (call.argument<Int>("years") ?: 25).coerceIn(1, 50)
        val keySize = (call.argument<Int>("keySize") ?: 2048).let { if (it == 4096) 4096 else 2048 }
        val generated = CertGen.generate(
            alias,
            password,
            call.argument<String>("cn") ?: "",
            call.argument<String>("o") ?: "",
            call.argument<String>("ou") ?: "",
            call.argument<String>("l") ?: "",
            call.argument<String>("st") ?: "",
            call.argument<String>("c") ?: "CN",
            years,
            keySize,
        )
        val filename = "$alias.p12"
        saveToDownloads(filename, generated.pkcs12)
        return mapOf(
            "alias" to alias,
            "filename" to filename,
            "sha1" to generated.sha1,
            "sha256" to generated.sha256,
            "notAfter" to generated.notAfter.time,
            "keySize" to keySize,
        )
    }

    private fun saveToDownloads(filename: String, bytes: ByteArray) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            val values = ContentValues().apply {
                put(MediaStore.Downloads.DISPLAY_NAME, filename)
                put(MediaStore.Downloads.MIME_TYPE, "application/x-pkcs12")
                put(MediaStore.Downloads.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS)
            }
            val resolver = context.contentResolver
            val uri = resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values)
                ?: throw IllegalStateException("could not create Downloads entry")
            resolver.openOutputStream(uri)?.use { it.write(bytes) }
                ?: throw IllegalStateException("could not write Downloads entry")
        } else {
            @Suppress("DEPRECATION")
            val dir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
            if (!dir.exists()) dir.mkdirs()
            FileOutputStream(File(dir, filename)).use { it.write(bytes) }
        }
    }

    companion object {
        const val CHANNEL = "dsh/cert"
    }
}

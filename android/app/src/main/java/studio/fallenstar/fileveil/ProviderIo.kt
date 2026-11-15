// SPDX-License-Identifier: MPL-2.0
package studio.fallenstar.fileveil

import android.os.CancellationSignal
import java.io.Closeable
import java.io.IOException
import java.util.concurrent.*
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

/** One bounded provider worker, with no task queue. A provider that ignores
 * Android cancellation cannot accumulate stuck workers or delay the UI result.
 * New provider work fails closed until that one call releases its worker. */
internal object ProviderIo {
    private val worker = ThreadPoolExecutor(1, 1, 0, TimeUnit.SECONDS, SynchronousQueue(), { job -> Thread(job, "fileveil-provider").apply { isDaemon = true } }, ThreadPoolExecutor.AbortPolicy())
    private val timer = Executors.newSingleThreadScheduledExecutor { job -> Thread(job, "fileveil-provider-deadline").apply { isDaemon = true } }
    internal class Scope(private val stop: AtomicBoolean) {
        val signal = CancellationSignal()
        private val cancelled = AtomicBoolean(false)
        private val descriptor = AtomicReference<Closeable?>()
        fun check() { if (cancelled.get() || stop.get() || Thread.currentThread().isInterrupted) throw IOException("Document operation cancelled or timed out") }
        fun attach(value: Closeable) { descriptor.set(value); try { check() } catch (error: Exception) { value.close(); throw error } }
        fun detach(value: Closeable) { descriptor.compareAndSet(value, null) }
        fun cancel() {
            cancelled.set(true)
            // Do not let a provider's cancellation binder stall the caller.
            timer.execute { try { descriptor.getAndSet(null)?.close() } finally { signal.cancel() } }
        }
    }
    fun <T> bounded(stop: AtomicBoolean = AtomicBoolean(false), timeoutMs: Long = 30_000, operation: (Scope) -> T): T {
        val scope = Scope(stop)
        val task = try { worker.submit<T> { scope.check(); operation(scope) } }
            catch (_: RejectedExecutionException) { throw IOException("A document provider is still busy after cancellation; wait for it to recover") }
        val watchdog = timer.scheduleAtFixedRate({ if (stop.get()) { scope.cancel(); task.cancel(true) } }, 100, 100, TimeUnit.MILLISECONDS)
        try { return task.get(timeoutMs, TimeUnit.MILLISECONDS) }
        catch (_: TimeoutException) { scope.cancel(); task.cancel(true); throw IOException("Document provider exceeded the 30-second operation deadline") }
        catch (_: CancellationException) { scope.cancel(); throw IOException("Document operation cancelled") }
        catch (error: ExecutionException) { throw (error.cause as? Exception ?: IOException("Document provider failed")) }
        finally { watchdog.cancel(false) }
    }
}

// FVPROV1 2775 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiJjNzg0ZjNmNjg1NzUzY2FlZTFlNGY1MTk1Y2E4YTc2NzUxMWYwMDE3NTg0YWE5N2NlMWRiMjFjNTk2MWZlMjZjIiwiY29weV9pZCI6InYwLjcuMC1iZXRhLjEiLCJjcmVhdGVkX2F0IjoiMjAyNi0xMS0xNSIsImVkaXRpb24iOiJiZXRhIiwiaXNzdWVyX3BvbGljeSI6bnVsbCwia2luZCI6ImNyZWF0ZSIsIm1vZGUiOiJzZWxmX3NpZ24iLCJwYXJlbnRfdmVyc2lvbiI6bnVsbCwicHJldmlvdXNfcmVjb3JkX3NoYTI1NiI6bnVsbCwic2NoZW1hIjoiZmlsZXZlaWwucHJvdmVuYW5jZS5zaWduYXR1cmUudjIiLCJzZXF1ZW5jZSI6MCwidHJhbnNmZXJfdG9fa2V5X2lkIjpudWxsLCJ2ZXJzaW9uIjoidjAuNy4wLWJldGEuMSIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL2FuZHJvaWQvYXBwL3NyYy9tYWluL2phdmEvc3R1ZGlvL2ZhbGxlbnN0YXIvZmlsZXZlaWwvUHJvdmlkZXJJby5rdCJ9LCJzaWduYXR1cmVzIjpbeyJrZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwicHVibGljX2tleV9oZXgiOiJhZGIzZTE3Y2QxMmY5NTZkMDA3MGUxNjYzZjUzMTUzN2ZjZWRmNzMwOGQwMTY1OGZlYTQ1NmZlZWE4ZjdmYmM1Iiwic2lnbmF0dXJlX2hleCI6IjE1NDU3ZmFkMzQyMmNmNDNhZmI2ODI5YWM5MGRkY2Q2NzQ1OTdhZDJkNjdkYTNlMzE0YjhlZjYxMzFjOWU4YmRhZWEyY2YwMjBlNTBiYzIzZjk2NjVjODY4M2ZlOWM0OWY2NjZmZWE2ZjQxNjUxNjIyMGVjN2M4ZTdhZDI0NzA5In1dfV0= FVPROV1-END

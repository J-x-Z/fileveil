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

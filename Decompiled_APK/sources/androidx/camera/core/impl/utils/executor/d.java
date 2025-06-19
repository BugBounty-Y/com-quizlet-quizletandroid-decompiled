package androidx.camera.core.impl.utils.executor;

import android.os.Handler;
import androidx.concurrent.futures.l;
import com.google.android.gms.internal.mlkit_vision_barcode.Y5;
import java.util.concurrent.Callable;
import java.util.concurrent.Delayed;
import java.util.concurrent.RunnableScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

/* loaded from: classes.dex */
public final class d implements RunnableScheduledFuture {
    public final AtomicReference a = new AtomicReference(null);
    public final long b;
    public final Callable c;
    public final l d;

    public d(Handler handler, long j, Callable callable) {
        this.b = j;
        this.c = callable;
        com.quizlet.data.repository.login.a aVar = new com.quizlet.data.repository.login.a();
        aVar.c = this;
        aVar.a = handler;
        aVar.b = callable;
        this.d = Y5.b(aVar);
    }

    @Override // java.util.concurrent.Future
    public final boolean cancel(boolean z) {
        return this.d.cancel(z);
    }

    @Override // java.lang.Comparable
    public final int compareTo(Delayed delayed) {
        TimeUnit timeUnit = TimeUnit.MILLISECONDS;
        return Long.compare(getDelay(timeUnit), delayed.getDelay(timeUnit));
    }

    @Override // java.util.concurrent.Future
    public final Object get() {
        return this.d.b.get();
    }

    @Override // java.util.concurrent.Delayed
    public final long getDelay(TimeUnit timeUnit) {
        return timeUnit.convert(this.b - System.currentTimeMillis(), TimeUnit.MILLISECONDS);
    }

    @Override // java.util.concurrent.Future
    public final boolean isCancelled() {
        return this.d.isCancelled();
    }

    @Override // java.util.concurrent.Future
    public final boolean isDone() {
        return this.d.b.isDone();
    }

    @Override // java.util.concurrent.RunnableScheduledFuture
    public final boolean isPeriodic() {
        return false;
    }

    @Override // java.util.concurrent.RunnableFuture, java.lang.Runnable
    public final void run() {
        androidx.concurrent.futures.i iVar = (androidx.concurrent.futures.i) this.a.getAndSet(null);
        if (iVar != null) {
            try {
                iVar.b(this.c.call());
            } catch (Exception e) {
                iVar.d(e);
            }
        }
    }

    @Override // java.util.concurrent.Future
    public final Object get(long j, TimeUnit timeUnit) {
        return this.d.b.get(j, timeUnit);
    }
}

package kotlinx.coroutines;

import java.lang.reflect.Method;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import kotlin.coroutines.CoroutineContext;

/* renamed from: kotlinx.coroutines.b0, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4975b0 extends AbstractC4973a0 implements J {
    public final Executor b;

    public C4975b0(Executor executor) {
        Method method;
        this.b = executor;
        Method method2 = kotlinx.coroutines.internal.a.a;
        try {
            ScheduledThreadPoolExecutor scheduledThreadPoolExecutor = executor instanceof ScheduledThreadPoolExecutor ? (ScheduledThreadPoolExecutor) executor : null;
            if (scheduledThreadPoolExecutor != null && (method = kotlinx.coroutines.internal.a.a) != null) {
                method.invoke(scheduledThreadPoolExecutor, Boolean.TRUE);
            }
        } catch (Throwable unused) {
        }
    }

    @Override // java.io.Closeable, java.lang.AutoCloseable
    public final void close() {
        Executor executor = this.b;
        ExecutorService executorService = executor instanceof ExecutorService ? (ExecutorService) executor : null;
        if (executorService != null) {
            executorService.shutdown();
        }
    }

    public final boolean equals(Object obj) {
        return (obj instanceof C4975b0) && ((C4975b0) obj).b == this.b;
    }

    @Override // kotlinx.coroutines.J
    public final void f(long j, C5028l c5028l) {
        Executor executor = this.b;
        ScheduledFuture<?> scheduledFutureSchedule = null;
        ScheduledExecutorService scheduledExecutorService = executor instanceof ScheduledExecutorService ? (ScheduledExecutorService) executor : null;
        if (scheduledExecutorService != null) {
            try {
                scheduledFutureSchedule = scheduledExecutorService.schedule(new com.google.android.gms.measurement.internal.A0(this, false, c5028l, 15), j, TimeUnit.MILLISECONDS);
            } catch (RejectedExecutionException e) {
                E.h(c5028l.e, E.a("The task was rejected", e));
            }
        }
        if (scheduledFutureSchedule != null) {
            c5028l.v(new C5022i(scheduledFutureSchedule, 0));
        } else {
            F.i.f(j, c5028l);
        }
    }

    public final int hashCode() {
        return System.identityHashCode(this.b);
    }

    @Override // kotlinx.coroutines.J
    public final Q i(long j, Runnable runnable, CoroutineContext coroutineContext) {
        Executor executor = this.b;
        ScheduledFuture<?> scheduledFutureSchedule = null;
        ScheduledExecutorService scheduledExecutorService = executor instanceof ScheduledExecutorService ? (ScheduledExecutorService) executor : null;
        if (scheduledExecutorService != null) {
            try {
                scheduledFutureSchedule = scheduledExecutorService.schedule(runnable, j, TimeUnit.MILLISECONDS);
            } catch (RejectedExecutionException e) {
                E.h(coroutineContext, E.a("The task was rejected", e));
            }
        }
        return scheduledFutureSchedule != null ? new P(scheduledFutureSchedule) : F.i.i(j, runnable, coroutineContext);
    }

    @Override // kotlinx.coroutines.AbstractC5040y
    public final void r(CoroutineContext coroutineContext, Runnable runnable) {
        try {
            this.b.execute(runnable);
        } catch (RejectedExecutionException e) {
            E.h(coroutineContext, E.a("The task was rejected", e));
            kotlinx.coroutines.scheduling.e eVar = O.a;
            kotlinx.coroutines.scheduling.d.b.r(coroutineContext, runnable);
        }
    }

    @Override // kotlinx.coroutines.AbstractC5040y
    public final String toString() {
        return this.b.toString();
    }
}

package io.reactivex.rxjava3.core;

import java.util.Objects;
import java.util.concurrent.TimeUnit;

/* loaded from: classes3.dex */
public abstract class o {
    static {
        Boolean.getBoolean("rx3.scheduler.use-nanotime");
        long jLongValue = Long.getLong("rx3.scheduler.drift-tolerance", 15L).longValue();
        String property = System.getProperty("rx3.scheduler.drift-tolerance-unit", "minutes");
        if ("seconds".equalsIgnoreCase(property)) {
            TimeUnit.SECONDS.toNanos(jLongValue);
        } else if ("milliseconds".equalsIgnoreCase(property)) {
            TimeUnit.MILLISECONDS.toNanos(jLongValue);
        } else {
            TimeUnit.MINUTES.toNanos(jLongValue);
        }
    }

    public abstract n a();

    public io.reactivex.rxjava3.disposables.b b(Runnable runnable) {
        return c(runnable, 0L, TimeUnit.NANOSECONDS);
    }

    public io.reactivex.rxjava3.disposables.b c(Runnable runnable, long j, TimeUnit timeUnit) {
        n nVarA = a();
        Objects.requireNonNull(runnable, "run is null");
        m mVar = new m(runnable, nVarA);
        nVarA.b(mVar, j, timeUnit);
        return mVar;
    }
}

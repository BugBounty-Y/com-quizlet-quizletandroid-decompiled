package kotlinx.coroutines;

import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.LockSupport;
import kotlin.coroutines.CoroutineContext;

/* loaded from: classes3.dex */
public final class F extends Y implements Runnable {
    private static volatile Thread _thread;
    private static volatile int debugStatus;
    public static final F i;
    public static final long j;

    static {
        Long l;
        F f = new F();
        i = f;
        f.n0(false);
        TimeUnit timeUnit = TimeUnit.MILLISECONDS;
        try {
            l = Long.getLong("kotlinx.coroutines.DefaultExecutor.keepAlive", 1000L);
        } catch (SecurityException unused) {
            l = 1000L;
        }
        j = timeUnit.toNanos(l.longValue());
    }

    @Override // kotlinx.coroutines.Y, kotlinx.coroutines.J
    public final Q i(long j2, Runnable runnable, CoroutineContext coroutineContext) {
        long j3 = j2 > 0 ? j2 >= 9223372036854L ? Long.MAX_VALUE : 1000000 * j2 : 0L;
        if (j3 >= 4611686018427387903L) {
            return v0.a;
        }
        long jNanoTime = System.nanoTime();
        V v = new V(j3 + jNanoTime, runnable);
        v0(jNanoTime, v);
        return v;
    }

    @Override // kotlinx.coroutines.Z
    public final Thread m0() {
        Thread thread;
        Thread thread2 = _thread;
        if (thread2 != null) {
            return thread2;
        }
        synchronized (this) {
            thread = _thread;
            if (thread == null) {
                thread = new Thread(this, "kotlinx.coroutines.DefaultExecutor");
                _thread = thread;
                thread.setContextClassLoader(i.getClass().getClassLoader());
                thread.setDaemon(true);
                thread.start();
            }
        }
        return thread;
    }

    @Override // kotlinx.coroutines.Z
    public final void q0(long j2, W w) {
        throw new RejectedExecutionException("DefaultExecutor was shut down. This error indicates that Dispatchers.shutdown() was invoked prior to completion of exiting coroutines, leaving coroutines in incomplete state. Please refer to Dispatchers.shutdown documentation for more details");
    }

    @Override // kotlinx.coroutines.Y
    public final void r0(Runnable runnable) {
        if (debugStatus == 4) {
            throw new RejectedExecutionException("DefaultExecutor was shut down. This error indicates that Dispatchers.shutdown() was invoked prior to completion of exiting coroutines, leaving coroutines in incomplete state. Please refer to Dispatchers.shutdown documentation for more details");
        }
        super.r0(runnable);
    }

    @Override // java.lang.Runnable
    public final void run() {
        boolean zU0;
        C0.a.set(this);
        try {
            synchronized (this) {
                int i2 = debugStatus;
                if (i2 == 2 || i2 == 3) {
                    if (zU0) {
                        return;
                    } else {
                        return;
                    }
                }
                debugStatus = 1;
                notifyAll();
                long j2 = Long.MAX_VALUE;
                while (true) {
                    Thread.interrupted();
                    long jO0 = o0();
                    if (jO0 == Long.MAX_VALUE) {
                        long jNanoTime = System.nanoTime();
                        if (j2 == Long.MAX_VALUE) {
                            j2 = j + jNanoTime;
                        }
                        long j3 = j2 - jNanoTime;
                        if (j3 <= 0) {
                            _thread = null;
                            w0();
                            if (u0()) {
                                return;
                            }
                            m0();
                            return;
                        }
                        if (jO0 > j3) {
                            jO0 = j3;
                        }
                    } else {
                        j2 = Long.MAX_VALUE;
                    }
                    if (jO0 > 0) {
                        int i3 = debugStatus;
                        if (i3 == 2 || i3 == 3) {
                            _thread = null;
                            w0();
                            if (u0()) {
                                return;
                            }
                            m0();
                            return;
                        }
                        LockSupport.parkNanos(this, jO0);
                    }
                }
            }
        } finally {
            _thread = null;
            w0();
            if (!u0()) {
                m0();
            }
        }
    }

    @Override // kotlinx.coroutines.Y, kotlinx.coroutines.Z
    public final void shutdown() {
        debugStatus = 4;
        super.shutdown();
    }

    @Override // kotlinx.coroutines.AbstractC5040y
    public final String toString() {
        return "DefaultExecutor";
    }

    public final synchronized void w0() {
        int i2 = debugStatus;
        if (i2 == 2 || i2 == 3) {
            debugStatus = 3;
            Y.f.set(this, null);
            Y.g.set(this, null);
            notifyAll();
        }
    }
}

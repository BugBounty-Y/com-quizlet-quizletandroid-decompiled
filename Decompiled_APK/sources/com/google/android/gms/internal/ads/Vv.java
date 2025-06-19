package com.google.android.gms.internal.ads;

import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.LockSupport;

/* loaded from: classes2.dex */
public abstract class Vv extends AtomicReference implements Runnable {
    public static final C4 a = new C4(8);
    public static final C4 b = new C4(8);

    public abstract Object a();

    public abstract String b();

    public final void c(Thread thread) {
        Runnable runnable = (Runnable) get();
        Uv uv = null;
        boolean z = false;
        int i = 0;
        while (true) {
            boolean z2 = runnable instanceof Uv;
            C4 c4 = b;
            if (!z2) {
                if (runnable != c4) {
                    break;
                }
            } else {
                uv = (Uv) runnable;
            }
            i++;
            if (i <= 1000) {
                Thread.yield();
            } else if (runnable == c4 || compareAndSet(runnable, c4)) {
                z = Thread.interrupted() || z;
                LockSupport.park(uv);
            }
            runnable = (Runnable) get();
        }
        if (z) {
            thread.interrupt();
        }
    }

    public abstract void d(Throwable th);

    public abstract void e(Object obj);

    public abstract boolean f();

    public final void g() {
        C4 c4 = b;
        C4 c42 = a;
        Runnable runnable = (Runnable) get();
        if (runnable instanceof Thread) {
            Uv uv = new Uv(this);
            uv.setExclusiveOwnerThread(Thread.currentThread());
            if (compareAndSet(runnable, uv)) {
                try {
                    Thread thread = (Thread) runnable;
                    thread.interrupt();
                    if (((Runnable) getAndSet(c42)) == c4) {
                        LockSupport.unpark(thread);
                    }
                } catch (Throwable th) {
                    if (((Runnable) getAndSet(c42)) == c4) {
                        LockSupport.unpark((Thread) runnable);
                    }
                    throw th;
                }
            }
        }
    }

    @Override // java.lang.Runnable
    public final void run() {
        Thread threadCurrentThread = Thread.currentThread();
        Object objA = null;
        if (compareAndSet(null, threadCurrentThread)) {
            boolean zF = f();
            C4 c4 = a;
            if (!zF) {
                try {
                    objA = a();
                } catch (Throwable th) {
                    try {
                        if (th instanceof InterruptedException) {
                            Thread.currentThread().interrupt();
                        }
                        if (!compareAndSet(threadCurrentThread, c4)) {
                            c(threadCurrentThread);
                        }
                        d(th);
                        return;
                    } catch (Throwable th2) {
                        if (!compareAndSet(threadCurrentThread, c4)) {
                            c(threadCurrentThread);
                        }
                        e(null);
                        throw th2;
                    }
                }
            }
            if (!compareAndSet(threadCurrentThread, c4)) {
                c(threadCurrentThread);
            }
            if (zF) {
                return;
            }
            e(objA);
        }
    }

    @Override // java.util.concurrent.atomic.AtomicReference
    public final String toString() {
        Runnable runnable = (Runnable) get();
        return android.support.v4.media.session.a.l(runnable == a ? "running=[DONE]" : runnable instanceof Uv ? "running=[INTERRUPTED]" : runnable instanceof Thread ? android.support.v4.media.session.a.B("running=[RUNNING ON ", ((Thread) runnable).getName(), "]") : "running=[NOT STARTED YET]", ", ", b());
    }
}

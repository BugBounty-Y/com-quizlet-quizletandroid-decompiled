package com.google.android.gms.internal.play_billing;

import java.util.concurrent.Callable;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.LockSupport;

/* loaded from: classes2.dex */
public final class F0 extends AtomicReference implements Runnable {
    public static final RunnableC3842v0 c = new RunnableC3842v0();
    public static final RunnableC3842v0 d = new RunnableC3842v0();
    public final Callable a;
    public final /* synthetic */ G0 b;

    public F0(G0 g0, Callable callable) {
        this.b = g0;
        callable.getClass();
        this.a = callable;
    }

    public final void a(Thread thread) {
        Runnable runnable = (Runnable) get();
        RunnableC3839u0 runnableC3839u0 = null;
        boolean z = false;
        int i = 0;
        while (true) {
            boolean z2 = runnable instanceof RunnableC3839u0;
            RunnableC3842v0 runnableC3842v0 = d;
            if (!z2) {
                if (runnable != runnableC3842v0) {
                    break;
                }
            } else {
                runnableC3839u0 = (RunnableC3839u0) runnable;
            }
            i++;
            if (i <= 1000) {
                Thread.yield();
            } else if (runnable == runnableC3842v0 || compareAndSet(runnable, runnableC3842v0)) {
                z = Thread.interrupted() || z;
                LockSupport.park(runnableC3839u0);
            }
            runnable = (Runnable) get();
        }
        if (z) {
            thread.interrupt();
        }
    }

    @Override // java.lang.Runnable
    public final void run() {
        Object objCall;
        Thread threadCurrentThread = Thread.currentThread();
        if (compareAndSet(null, threadCurrentThread)) {
            G0 g0 = this.b;
            boolean zIsDone = g0.isDone();
            RunnableC3842v0 runnableC3842v0 = c;
            if (zIsDone) {
                objCall = null;
            } else {
                try {
                    objCall = this.a.call();
                } catch (Throwable th) {
                    try {
                        if (th instanceof InterruptedException) {
                            Thread.currentThread().interrupt();
                        }
                        if (!compareAndSet(threadCurrentThread, runnableC3842v0)) {
                            a(threadCurrentThread);
                        }
                        g0.e(th);
                        return;
                    } catch (Throwable th2) {
                        if (!compareAndSet(threadCurrentThread, runnableC3842v0)) {
                            a(threadCurrentThread);
                        }
                        g0.getClass();
                        if (AbstractC3816m0.f.E(g0, null, AbstractC3816m0.g)) {
                            AbstractC3816m0.i(g0);
                        }
                        throw th2;
                    }
                }
            }
            if (!compareAndSet(threadCurrentThread, runnableC3842v0)) {
                a(threadCurrentThread);
            }
            if (zIsDone) {
                return;
            }
            g0.getClass();
            if (objCall == null) {
                objCall = AbstractC3816m0.g;
            }
            if (AbstractC3816m0.f.E(g0, null, objCall)) {
                AbstractC3816m0.i(g0);
            }
        }
    }

    @Override // java.util.concurrent.atomic.AtomicReference
    public final String toString() {
        Runnable runnable = (Runnable) get();
        return android.support.v4.media.session.a.l(runnable == c ? "running=[DONE]" : runnable instanceof RunnableC3839u0 ? "running=[INTERRUPTED]" : runnable instanceof Thread ? android.support.v4.media.session.a.B("running=[RUNNING ON ", ((Thread) runnable).getName(), "]") : "running=[NOT STARTED YET]", ", ", this.a.toString());
    }
}

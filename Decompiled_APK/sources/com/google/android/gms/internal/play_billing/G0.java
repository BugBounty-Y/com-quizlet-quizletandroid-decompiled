package com.google.android.gms.internal.play_billing;

import java.util.concurrent.Callable;
import java.util.concurrent.RunnableFuture;
import java.util.concurrent.locks.LockSupport;

/* loaded from: classes2.dex */
public final class G0 extends AbstractC3830r0 implements RunnableFuture {
    public volatile F0 h;

    public G0(Callable callable) {
        this.h = new F0(this, callable);
    }

    @Override // com.google.android.gms.internal.play_billing.AbstractC3816m0
    public final String c() {
        F0 f0 = this.h;
        return f0 != null ? android.support.v4.media.session.a.B("task=[", f0.toString(), "]") : super.c();
    }

    @Override // com.google.android.gms.internal.play_billing.AbstractC3816m0
    public final void d() {
        F0 f0;
        Object obj = this.a;
        if (((obj instanceof C3786c0) && ((C3786c0) obj).a) && (f0 = this.h) != null) {
            RunnableC3842v0 runnableC3842v0 = F0.d;
            RunnableC3842v0 runnableC3842v02 = F0.c;
            Runnable runnable = (Runnable) f0.get();
            if (runnable instanceof Thread) {
                RunnableC3839u0 runnableC3839u0 = new RunnableC3839u0(f0);
                runnableC3839u0.setExclusiveOwnerThread(Thread.currentThread());
                if (f0.compareAndSet(runnable, runnableC3839u0)) {
                    try {
                        Thread thread = (Thread) runnable;
                        thread.interrupt();
                        if (((Runnable) f0.getAndSet(runnableC3842v02)) == runnableC3842v0) {
                            LockSupport.unpark(thread);
                        }
                    } catch (Throwable th) {
                        if (((Runnable) f0.getAndSet(runnableC3842v02)) == runnableC3842v0) {
                            LockSupport.unpark((Thread) runnable);
                        }
                        throw th;
                    }
                }
            }
        }
        this.h = null;
    }

    @Override // java.util.concurrent.RunnableFuture, java.lang.Runnable
    public final void run() {
        F0 f0 = this.h;
        if (f0 != null) {
            f0.run();
        }
        this.h = null;
    }
}

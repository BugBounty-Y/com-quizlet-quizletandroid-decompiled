package com.google.android.gms.internal.play_billing;

import com.google.android.gms.internal.ads.C2029ew;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

/* loaded from: classes2.dex */
public final class D0 implements Runnable {
    public E0 a;

    @Override // java.lang.Runnable
    public final void run() {
        InterfaceFutureC3845w0 interfaceFutureC3845w0;
        C3789d0 c3789d0;
        E0 e0 = this.a;
        if (e0 == null || (interfaceFutureC3845w0 = e0.h) == null) {
            return;
        }
        this.a = null;
        if (interfaceFutureC3845w0.isDone()) {
            Object obj = e0.a;
            if (obj == null) {
                if (interfaceFutureC3845w0.isDone()) {
                    if (AbstractC3816m0.f.E(e0, null, AbstractC3816m0.f(interfaceFutureC3845w0))) {
                        AbstractC3816m0.i(e0);
                        return;
                    }
                    return;
                }
                RunnableC3798g0 runnableC3798g0 = new RunnableC3798g0(e0, interfaceFutureC3845w0);
                if (AbstractC3816m0.f.E(e0, null, runnableC3798g0)) {
                    try {
                        interfaceFutureC3845w0.b(runnableC3798g0, EnumC3828q0.a);
                        return;
                    } catch (Throwable th) {
                        try {
                            c3789d0 = new C3789d0(th);
                        } catch (Error | Exception unused) {
                            c3789d0 = C3789d0.b;
                        }
                        AbstractC3816m0.f.E(e0, runnableC3798g0, c3789d0);
                        return;
                    }
                }
                obj = e0.a;
            }
            if (obj instanceof C3786c0) {
                interfaceFutureC3845w0.cancel(((C3786c0) obj).a);
                return;
            }
            return;
        }
        try {
            ScheduledFuture scheduledFuture = e0.i;
            e0.i = null;
            String str = "Timed out";
            if (scheduledFuture != null) {
                try {
                    long jAbs = Math.abs(scheduledFuture.getDelay(TimeUnit.MILLISECONDS));
                    if (jAbs > 10) {
                        str = "Timed out (timeout delayed by " + jAbs + " ms after scheduled time)";
                    }
                } catch (Throwable th2) {
                    e0.e(new C2029ew(str, 1));
                    throw th2;
                }
            }
            e0.e(new C2029ew(str + ": " + interfaceFutureC3845w0.toString(), 1));
        } finally {
            interfaceFutureC3845w0.cancel(true);
        }
    }
}

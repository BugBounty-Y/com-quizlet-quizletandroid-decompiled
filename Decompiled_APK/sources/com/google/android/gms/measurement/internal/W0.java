package com.google.android.gms.measurement.internal;

import java.util.concurrent.ScheduledExecutorService;

/* loaded from: classes2.dex */
public final class W0 implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ InterfaceC3897v b;
    public final /* synthetic */ X0 c;

    public /* synthetic */ W0(X0 x0, InterfaceC3897v interfaceC3897v, int i) {
        this.a = i;
        this.b = interfaceC3897v;
        this.c = x0;
    }

    @Override // java.lang.Runnable
    public final void run() {
        ScheduledExecutorService scheduledExecutorService;
        switch (this.a) {
            case 0:
                X0 x0 = this.c;
                synchronized (x0) {
                    try {
                        x0.a = false;
                        Y0 y0 = x0.c;
                        if (!y0.b0()) {
                            I i = ((Y) y0.b).i;
                            Y.k(i);
                            i.o.f("Connected to service");
                            InterfaceC3897v interfaceC3897v = this.b;
                            y0.S();
                            y0.e = interfaceC3897v;
                            y0.h0();
                            y0.g0();
                        }
                    } finally {
                    }
                }
                return;
            default:
                X0 x02 = this.c;
                synchronized (x02) {
                    try {
                        x02.a = false;
                        Y0 y02 = x02.c;
                        if (!y02.b0()) {
                            I i2 = ((Y) y02.b).i;
                            Y.k(i2);
                            i2.n.f("Connected to remote service");
                            InterfaceC3897v interfaceC3897v2 = this.b;
                            y02.S();
                            y02.e = interfaceC3897v2;
                            y02.h0();
                            y02.g0();
                        }
                    } finally {
                    }
                }
                Y0 y03 = this.c.c;
                if (!((Y) y03.b).g.f0(null, AbstractC3893t.o1) || (scheduledExecutorService = y03.h) == null) {
                    return;
                }
                scheduledExecutorService.shutdownNow();
                y03.h = null;
                return;
        }
    }
}

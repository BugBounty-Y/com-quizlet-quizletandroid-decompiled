package com.google.android.gms.measurement.internal;

import android.os.SystemClock;
import android.text.TextUtils;
import java.util.concurrent.atomic.AtomicReference;
import org.json.JSONException;

/* renamed from: com.google.android.gms.measurement.internal.y0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class RunnableC3904y0 implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ long b;
    public final /* synthetic */ D0 c;

    public /* synthetic */ RunnableC3904y0(D0 d0, long j, int i) {
        this.a = i;
        this.b = j;
        this.c = d0;
    }

    @Override // java.lang.Runnable
    public final void run() throws JSONException {
        long jElapsedRealtime;
        switch (this.a) {
            case 0:
                Y y = (Y) this.c.b;
                O o = y.h;
                Y.h(o);
                N n = o.m;
                long j = this.b;
                n.b(j);
                I i = y.i;
                Y.k(i);
                i.n.g("Session timeout duration set", Long.valueOf(j));
                break;
            default:
                D0 d0 = this.c;
                d0.S();
                d0.Q();
                Y y2 = (Y) d0.b;
                I i2 = y2.i;
                Y.k(i2);
                i2.n.f("Resetting analytics data (FE)");
                g1 g1Var = y2.k;
                Y.j(g1Var);
                g1Var.S();
                androidx.compose.foundation.lazy.layout.p0 p0Var = g1Var.g;
                ((f1) p0Var.c).a();
                Y y3 = (Y) ((g1) p0Var.d).b;
                if (y3.g.f0(null, AbstractC3893t.b1)) {
                    y3.n.getClass();
                    jElapsedRealtime = SystemClock.elapsedRealtime();
                    p0Var.a = jElapsedRealtime;
                } else {
                    p0Var.a = 0L;
                    jElapsedRealtime = 0;
                }
                p0Var.b = jElapsedRealtime;
                y2.n().Z();
                boolean z = !y2.a();
                O o2 = y2.h;
                Y.h(o2);
                o2.h.b(this.b);
                Y y4 = (Y) o2.b;
                O o3 = y4.h;
                Y.h(o3);
                if (!TextUtils.isEmpty(o3.x.l())) {
                    o2.x.m(null);
                }
                o2.r.b(0L);
                o2.s.b(0L);
                if (!y4.g.T()) {
                    o2.a0(z);
                }
                o2.y.m(null);
                o2.z.b(0L);
                o2.A.i(null);
                Y0 y0R = y2.r();
                y0R.S();
                y0R.Q();
                zzr zzrVarF0 = y0R.f0(false);
                y0R.j0();
                ((Y) y0R.b).o().W();
                y0R.i0(new T0(y0R, zzrVarF0, 0));
                Y.j(g1Var);
                g1Var.f.E();
                d0.t = z;
                y2.r().X(new AtomicReference());
                break;
        }
    }
}

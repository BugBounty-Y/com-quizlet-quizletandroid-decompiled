package com.google.android.gms.measurement.internal;

import android.app.BroadcastOptions;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.os.SystemClock;

/* loaded from: classes2.dex */
public final class f1 extends AbstractC3876k {
    public final /* synthetic */ int e;
    public final /* synthetic */ Object f;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ f1(Object obj, InterfaceC3873i0 interfaceC3873i0, int i) {
        super(interfaceC3873i0);
        this.e = i;
        this.f = obj;
    }

    @Override // com.google.android.gms.measurement.internal.AbstractC3876k
    public final void b() {
        switch (this.e) {
            case 0:
                androidx.compose.foundation.lazy.layout.p0 p0Var = (androidx.compose.foundation.lazy.layout.p0) this.f;
                g1 g1Var = (g1) p0Var.d;
                g1Var.S();
                Y y = (Y) g1Var.b;
                y.n.getClass();
                p0Var.k(SystemClock.elapsedRealtime(), false, false);
                C3884o c3884o = y.q;
                Y.g(c3884o);
                y.n.getClass();
                c3884o.V(SystemClock.elapsedRealtime());
                break;
            case 1:
                k1 k1Var = (k1) this.f;
                k1Var.Q();
                I i = ((Y) k1Var.b).i;
                Y.k(i);
                i.o.f("Starting upload from DelayedRunnable");
                k1Var.c.X();
                break;
            default:
                r1 r1Var = (r1) this.f;
                r1Var.i().S();
                String str = (String) r1Var.q.pollFirst();
                if (str != null) {
                    ((com.google.android.gms.common.util.b) r1Var.f()).getClass();
                    r1Var.I = SystemClock.elapsedRealtime();
                    r1Var.c().o.g("Sending trigger URI notification to app", str);
                    Intent intent = new Intent();
                    intent.setAction("com.google.android.gms.measurement.TRIGGERS_AVAILABLE");
                    intent.setPackage(str);
                    Context context = r1Var.l.a;
                    if (Build.VERSION.SDK_INT < 34) {
                        context.sendBroadcast(intent);
                    } else {
                        context.sendBroadcast(intent, null, BroadcastOptions.makeBasic().setShareIdentityEnabled(true).toBundle());
                    }
                }
                r1Var.E();
                break;
        }
    }
}

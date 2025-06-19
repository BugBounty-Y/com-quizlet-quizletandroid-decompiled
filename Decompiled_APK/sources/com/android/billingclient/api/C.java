package com.android.billingclient.api;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.IntentFilter;
import android.os.Build;
import android.os.Bundle;
import androidx.camera.camera2.internal.p0;
import com.google.android.gms.internal.play_billing.AbstractC3819n0;
import com.google.android.gms.internal.play_billing.C3843v1;
import com.google.android.gms.internal.play_billing.K1;
import com.google.android.gms.internal.play_billing.W0;
import com.google.android.gms.internal.play_billing.Z0;
import com.google.android.gms.measurement.internal.r1;

/* loaded from: classes.dex */
public final class C extends BroadcastReceiver {
    public final /* synthetic */ int a = 0;
    public boolean b;
    public boolean c;
    public final Object d;

    public C(p0 p0Var, boolean z) {
        this.d = p0Var;
        this.c = z;
    }

    public synchronized void a(Context context, IntentFilter intentFilter) {
        try {
            if (this.b) {
                return;
            }
            if (Build.VERSION.SDK_INT >= 33) {
                context.registerReceiver(this, intentFilter, true != this.c ? 4 : 2);
            } else {
                context.registerReceiver(this, intentFilter);
            }
            this.b = true;
        } catch (Throwable th) {
            throw th;
        }
    }

    public void b() {
        r1 r1Var = (r1) this.d;
        r1Var.k();
        r1Var.i().S();
        r1Var.i().S();
        if (this.b) {
            r1Var.c().o.f("Unregistering connectivity change receiver");
            this.b = false;
            this.c = false;
            try {
                r1Var.l.a.unregisterReceiver(this);
            } catch (IllegalArgumentException e) {
                r1Var.c().g.g("Failed to unregister the network broadcast receiver", e);
            }
        }
    }

    public synchronized void c(Context context) {
        if (!this.b) {
            AbstractC3819n0.f("BillingBroadcastManager", "Receiver is not registered.");
        } else {
            context.unregisterReceiver(this);
            this.b = false;
        }
    }

    public void d(Bundle bundle, e eVar, int i) {
        W0 w0Q;
        try {
            if (bundle.getByteArray("FAILURE_LOGGING_PAYLOAD") == null) {
                ((androidx.work.impl.model.c) ((p0) this.d).a).C(y.b(23, i, eVar));
                return;
            }
            androidx.work.impl.model.c cVar = (androidx.work.impl.model.c) ((p0) this.d).a;
            byte[] byteArray = bundle.getByteArray("FAILURE_LOGGING_PAYLOAD");
            int i2 = W0.a;
            synchronized (W0.class) {
                int i3 = W0.a;
                C3843v1 c3843v1 = C3843v1.c;
                w0Q = Z0.q();
                int i4 = W0.a;
            }
            cVar.C(K1.n(byteArray, w0Q));
        } catch (Throwable unused) {
            AbstractC3819n0.f("BillingBroadcastManager", "Failed parsing Api failure.");
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:51:0x0158  */
    /* JADX WARN: Removed duplicated region for block: B:52:0x0164  */
    @Override // android.content.BroadcastReceiver
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void onReceive(android.content.Context r11, android.content.Intent r12) {
        /*
            Method dump skipped, instructions count: 374
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.android.billingclient.api.C.onReceive(android.content.Context, android.content.Intent):void");
    }

    public C(r1 r1Var) {
        com.google.android.gms.common.internal.u.h(r1Var);
        this.d = r1Var;
    }
}

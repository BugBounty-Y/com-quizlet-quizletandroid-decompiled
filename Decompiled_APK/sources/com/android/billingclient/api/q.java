package com.android.billingclient.api;

import android.content.ComponentName;
import android.content.ServiceConnection;
import android.os.IBinder;
import android.os.IInterface;
import androidx.appcompat.app.J;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.play_billing.AbstractBinderC3785c;
import com.google.android.gms.internal.play_billing.AbstractC3819n0;
import com.google.android.gms.internal.play_billing.C3782b;
import com.google.android.gms.internal.play_billing.InterfaceC3788d;
import com.google.android.gms.internal.play_billing.J1;
import com.google.android.gms.internal.play_billing.K1;
import com.google.android.gms.internal.play_billing.N1;
import com.google.android.gms.internal.play_billing.O1;
import com.google.android.gms.internal.play_billing.Q1;
import com.google.android.gms.internal.play_billing.g2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class q implements ServiceConnection {
    public final com.quizlet.billing.manager.f a;
    public final /* synthetic */ C1473b b;

    public /* synthetic */ q(C1473b c1473b, com.quizlet.billing.manager.f fVar) {
        this.b = c1473b;
        this.a = fVar;
    }

    public final void a(e result) {
        synchronized (this.b.a) {
            try {
                if (this.b.b == 3) {
                    return;
                }
                com.quizlet.billing.manager.f fVar = this.a;
                fVar.getClass();
                Intrinsics.checkNotNullParameter(result, "result");
                if (fVar.f.s() || fVar.f.r()) {
                    return;
                }
                fVar.f.onSuccess(Integer.valueOf(result.a));
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    @Override // android.content.ServiceConnection
    public final void onBindingDied(ComponentName componentName) {
        boolean z;
        AbstractC3819n0.f("BillingClient", "Billing service died.");
        try {
            C1473b c1473b = this.b;
            synchronized (c1473b.a) {
                z = true;
                if (c1473b.b != 1) {
                    z = false;
                }
            }
            if (z) {
                androidx.work.impl.model.c cVar = this.b.g;
                J1 j1R = K1.r();
                j1R.g(6);
                N1 n1R = O1.r();
                n1R.g(ContentType.USER_GENERATED_LONG_FORM_ON_DEMAND);
                j1R.f(n1R);
                cVar.C((K1) j1R.c());
            } else {
                this.b.g.E(Q1.n());
            }
        } catch (Throwable th) {
            AbstractC3819n0.g("BillingClient", "Unable to log.", th);
        }
        synchronized (this.b.a) {
            if (this.b.b != 3 && this.b.b != 0) {
                this.b.p(0);
                this.b.q();
                this.a.getClass();
            }
        }
    }

    @Override // android.content.ServiceConnection
    public final void onServiceConnected(ComponentName componentName, IBinder iBinder) {
        InterfaceC3788d c3782b;
        AbstractC3819n0.e("BillingClient", "Billing service connected.");
        synchronized (this.b.a) {
            try {
                if (this.b.b == 3) {
                    return;
                }
                C1473b c1473b = this.b;
                int i = AbstractBinderC3785c.b;
                if (iBinder == null) {
                    c3782b = null;
                } else {
                    IInterface iInterfaceQueryLocalInterface = iBinder.queryLocalInterface("com.android.vending.billing.IInAppBillingService");
                    c3782b = iInterfaceQueryLocalInterface instanceof InterfaceC3788d ? (InterfaceC3788d) iInterfaceQueryLocalInterface : new C3782b(iBinder, "com.android.vending.billing.IInAppBillingService", 6);
                }
                c1473b.h = c3782b;
                C1473b c1473b2 = this.b;
                if (C1473b.i(new androidx.camera.core.impl.utils.executor.c(this, 3), 30000L, new J(this, 14), c1473b2.v(), c1473b2.m()) == null) {
                    C1473b c1473b3 = this.b;
                    e eVarJ = c1473b3.j();
                    c1473b3.x(25, 6, eVarJ);
                    a(eVarJ);
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    @Override // android.content.ServiceConnection
    public final void onServiceDisconnected(ComponentName componentName) {
        boolean z;
        AbstractC3819n0.f("BillingClient", "Billing service disconnected.");
        try {
            C1473b c1473b = this.b;
            synchronized (c1473b.a) {
                z = true;
                if (c1473b.b != 1) {
                    z = false;
                }
            }
            if (z) {
                androidx.work.impl.model.c cVar = this.b.g;
                J1 j1R = K1.r();
                j1R.g(6);
                N1 n1R = O1.r();
                n1R.g(ContentType.USER_GENERATED_SHORT_FORM_ON_DEMAND);
                j1R.f(n1R);
                cVar.C((K1) j1R.c());
            } else {
                this.b.g.G(g2.n());
            }
        } catch (Throwable th) {
            AbstractC3819n0.g("BillingClient", "Unable to log.", th);
        }
        synchronized (this.b.a) {
            try {
                if (this.b.b == 3) {
                    return;
                }
                this.b.p(0);
                this.a.getClass();
            } finally {
            }
        }
    }
}

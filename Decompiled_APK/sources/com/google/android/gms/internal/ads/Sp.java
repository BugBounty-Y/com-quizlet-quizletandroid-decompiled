package com.google.android.gms.internal.ads;

import android.app.Activity;
import android.content.Context;
import android.os.Bundle;
import android.os.RemoteException;
import com.google.android.gms.ads.internal.client.C1605l0;
import com.google.android.gms.ads.internal.client.InterfaceC1609n0;
import com.google.android.gms.ads.internal.client.zzm;
import com.google.android.gms.ads.internal.util.client.VersionInfoParcel;

/* loaded from: classes2.dex */
public final class Sp extends AbstractBinderC2398nc {
    public final Qp b;
    public final Np c;
    public final String d;
    public final C1893bq e;
    public final Context f;
    public final VersionInfoParcel g;
    public final P4 h;
    public final Hk i;
    public C2105gk j;
    public boolean k = ((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.J0)).booleanValue();

    public Sp(String str, Qp qp, Context context, Np np, C1893bq c1893bq, VersionInfoParcel versionInfoParcel, P4 p4, Hk hk) {
        this.d = str;
        this.b = qp;
        this.c = np;
        this.e = c1893bq;
        this.f = context;
        this.g = versionInfoParcel;
        this.h = p4;
        this.i = hk;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2441oc
    public final synchronized void A2(boolean z) {
        com.google.android.gms.common.internal.u.d("setImmersiveMode must be called on the main UI thread.");
        this.k = z;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2441oc
    public final synchronized void C2(zzm zzmVar, InterfaceC2741vc interfaceC2741vc) {
        e4(zzmVar, interfaceC2741vc, 3);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2441oc
    public final synchronized void D(com.google.android.gms.dynamic.a aVar) {
        c2(aVar, this.k);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2441oc
    public final synchronized void Q0(zzbxe zzbxeVar) {
        com.google.android.gms.common.internal.u.d("#008 Must be called on the main UI thread.");
        C1893bq c1893bq = this.e;
        c1893bq.a = zzbxeVar.a;
        c1893bq.b = zzbxeVar.b;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2441oc
    public final void R0(InterfaceC2569rc interfaceC2569rc) {
        com.google.android.gms.common.internal.u.d("#008 Must be called on the main UI thread.");
        this.c.d.set(interfaceC2569rc);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2441oc
    public final synchronized void Z2(zzm zzmVar, InterfaceC2741vc interfaceC2741vc) {
        e4(zzmVar, interfaceC2741vc, 2);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2441oc
    public final com.google.android.gms.ads.internal.client.s0 a() {
        C2105gk c2105gk;
        if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.H6)).booleanValue() && (c2105gk = this.j) != null) {
            return c2105gk.f;
        }
        return null;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2441oc
    public final synchronized void c2(com.google.android.gms.dynamic.a aVar, boolean z) {
        com.google.android.gms.common.internal.u.d("#008 Must be called on the main UI thread.");
        if (this.j == null) {
            com.google.android.gms.ads.internal.util.client.i.h("Rewarded can not be shown before loaded");
            this.c.r(AbstractC1972di.x(9, null, null));
            return;
        }
        if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.U2)).booleanValue()) {
            this.h.b.c(new Throwable().getStackTrace());
        }
        this.j.b((Activity) com.google.android.gms.dynamic.b.I3(aVar), z);
    }

    public final synchronized void e4(zzm zzmVar, InterfaceC2741vc interfaceC2741vc, int i) {
        try {
            boolean z = false;
            if (!zzmVar.c.getBoolean("is_sdk_preload", false)) {
                if (((Boolean) U7.k.o()).booleanValue()) {
                    if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.hb)).booleanValue()) {
                        z = true;
                    }
                }
                if (this.g.c < ((Integer) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.ib)).intValue() || !z) {
                    com.google.android.gms.common.internal.u.d("#008 Must be called on the main UI thread.");
                }
            }
            Np np = this.c;
            np.c.set(interfaceC2741vc);
            com.google.android.gms.ads.internal.util.F f = com.google.android.gms.ads.internal.j.C.c;
            if (com.google.android.gms.ads.internal.util.F.g(this.f) && zzmVar.s == null) {
                com.google.android.gms.ads.internal.util.client.i.e("Failed to load the ad because app ID is missing.");
                np.m0(AbstractC1972di.x(4, null, null));
                return;
            }
            if (this.j != null) {
                return;
            }
            Op op = new Op();
            Qp qp = this.b;
            qp.h.o.b = i;
            qp.a(zzmVar, this.d, op, new C2881yn(this, 27));
        } catch (Throwable th) {
            throw th;
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2441oc
    public final synchronized String f() {
        Ug ug;
        C2105gk c2105gk = this.j;
        if (c2105gk == null || (ug = c2105gk.f) == null) {
            return null;
        }
        return ug.a;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2441oc
    public final InterfaceC2312lc j() {
        com.google.android.gms.common.internal.u.d("#008 Must be called on the main UI thread.");
        C2105gk c2105gk = this.j;
        if (c2105gk != null) {
            return c2105gk.q;
        }
        return null;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2441oc
    public final boolean o() {
        com.google.android.gms.common.internal.u.d("#008 Must be called on the main UI thread.");
        C2105gk c2105gk = this.j;
        return (c2105gk == null || c2105gk.t) ? false : true;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2441oc
    public final void p0(C2784wc c2784wc) {
        com.google.android.gms.common.internal.u.d("#008 Must be called on the main UI thread.");
        this.c.f.set(c2784wc);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2441oc
    public final void w2(InterfaceC1609n0 interfaceC1609n0) {
        com.google.android.gms.common.internal.u.d("setOnPaidEventListener must be called on the main UI thread.");
        try {
            if (!interfaceC1609n0.f()) {
                this.i.b();
            }
        } catch (RemoteException unused) {
            com.google.android.gms.ads.internal.util.client.i.k(3);
        }
        this.c.h.set(interfaceC1609n0);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2441oc
    public final void x1(C1605l0 c1605l0) {
        Np np = this.c;
        if (c1605l0 == null) {
            np.b.set(null);
        } else {
            np.b.set(new Rp(this, c1605l0, 0));
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2441oc
    public final Bundle zzb() {
        Bundle bundle;
        com.google.android.gms.common.internal.u.d("#008 Must be called on the main UI thread.");
        C2105gk c2105gk = this.j;
        if (c2105gk == null) {
            return new Bundle();
        }
        C2746vh c2746vh = c2105gk.o;
        synchronized (c2746vh) {
            bundle = new Bundle(c2746vh.c);
        }
        return bundle;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2441oc
    public final String zze() {
        return this.d;
    }
}

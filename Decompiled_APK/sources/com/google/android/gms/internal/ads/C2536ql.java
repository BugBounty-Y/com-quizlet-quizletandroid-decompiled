package com.google.android.gms.internal.ads;

import android.content.Context;
import android.os.RemoteException;
import com.google.android.gms.ads.internal.client.InterfaceC1603k0;
import com.google.android.gms.ads.internal.overlay.AdOverlayInfoParcel;
import com.google.android.gms.ads.internal.util.client.VersionInfoParcel;

/* renamed from: com.google.android.gms.internal.ads.ql, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2536ql implements com.google.android.gms.ads.internal.overlay.j, InterfaceC1681De {
    public final Context a;
    public final VersionInfoParcel b;
    public C2493pl c;
    public InterfaceC2529qe d;
    public boolean e;
    public boolean f;
    public long g;
    public InterfaceC1603k0 h;
    public boolean i;

    public C2536ql(Context context, VersionInfoParcel versionInfoParcel) {
        this.a = context;
        this.b = versionInfoParcel;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1681De
    public final synchronized void A(String str, int i, String str2, boolean z) {
        if (z) {
            com.google.android.gms.ads.internal.util.A.l("Ad inspector loaded.");
            this.e = true;
            b("");
            return;
        }
        com.google.android.gms.ads.internal.util.client.i.h("Ad inspector failed to load.");
        try {
            com.google.android.gms.ads.internal.j.C.h.h("InspectorUi.onAdWebViewFinishedLoading 0", new Exception("Failed to load UI. Error code: " + i + ", Description: " + str + ", Failing URL: " + str2));
            InterfaceC1603k0 interfaceC1603k0 = this.h;
            if (interfaceC1603k0 != null) {
                interfaceC1603k0.T1(AbstractC1972di.x(17, null, null));
            }
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.j.C.h.h("InspectorUi.onAdWebViewFinishedLoading 1", e);
        }
        this.i = true;
        this.d.destroy();
    }

    @Override // com.google.android.gms.ads.internal.overlay.j
    public final synchronized void I3() {
        this.f = true;
        b("");
    }

    @Override // com.google.android.gms.ads.internal.overlay.j
    public final void L2() {
    }

    @Override // com.google.android.gms.ads.internal.overlay.j
    public final synchronized void X(int i) {
        this.d.destroy();
        if (!this.i) {
            com.google.android.gms.ads.internal.util.A.l("Inspector closed.");
            InterfaceC1603k0 interfaceC1603k0 = this.h;
            if (interfaceC1603k0 != null) {
                try {
                    interfaceC1603k0.T1(null);
                } catch (RemoteException unused) {
                }
            }
        }
        this.f = false;
        this.e = false;
        this.g = 0L;
        this.i = false;
        this.h = null;
    }

    @Override // com.google.android.gms.ads.internal.overlay.j
    public final void Y3() {
    }

    public final synchronized void a(InterfaceC1603k0 interfaceC1603k0, C2432o9 c2432o9, C1956d9 c1956d9, C2432o9 c2432o92) {
        if (c(interfaceC1603k0)) {
            try {
                com.google.android.gms.ads.internal.j jVar = com.google.android.gms.ads.internal.j.C;
                L9 l9 = jVar.d;
                InterfaceC2529qe interfaceC2529qeG = L9.g(this.a, null, new com.bumptech.glide.load.engine.cache.f(0, 0, 0), this.b, null, new C2429o6(), null, null, null, null, null, null, null, "", false, false);
                this.d = interfaceC2529qeG;
                C1669Be c1669BeL = interfaceC2529qeG.L();
                if (c1669BeL == null) {
                    com.google.android.gms.ads.internal.util.client.i.h("Failed to obtain a web view for the ad inspector");
                    try {
                        jVar.h.h("InspectorUi.openInspector 2", new NullPointerException("Failed to obtain a web view for the ad inspector"));
                        interfaceC1603k0.T1(AbstractC1972di.x(17, "Failed to obtain a web view for the ad inspector", null));
                        return;
                    } catch (RemoteException e) {
                        com.google.android.gms.ads.internal.j.C.h.h("InspectorUi.openInspector 3", e);
                        return;
                    }
                }
                this.h = interfaceC1603k0;
                Context context = this.a;
                c1669BeL.q(null, null, null, null, null, false, null, null, null, null, null, null, null, c2432o9, null, new C2861y9(context), c1956d9, c2432o92, null);
                c1669BeL.g = this;
                this.d.loadUrl((String) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.V8));
                assistantMode.utils.studiableMetadata.b.a0(context, new AdOverlayInfoParcel(this, this.d, this.b), true, null);
                jVar.k.getClass();
                this.g = System.currentTimeMillis();
            } catch (zzcfn e2) {
                com.google.android.gms.ads.internal.util.client.i.i("Failed to obtain a web view for the ad inspector", e2);
                try {
                    com.google.android.gms.ads.internal.j.C.h.h("InspectorUi.openInspector 0", e2);
                    interfaceC1603k0.T1(AbstractC1972di.x(17, "Failed to obtain a web view for the ad inspector", null));
                } catch (RemoteException e3) {
                    com.google.android.gms.ads.internal.j.C.h.h("InspectorUi.openInspector 1", e3);
                }
            }
        }
    }

    public final synchronized void b(String str) {
        if (this.e && this.f) {
            AbstractC2270kd.f.execute(new Qv(29, this, str));
        }
    }

    public final synchronized boolean c(InterfaceC1603k0 interfaceC1603k0) {
        if (!((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.U8)).booleanValue()) {
            com.google.android.gms.ads.internal.util.client.i.h("Ad inspector had an internal error.");
            try {
                interfaceC1603k0.T1(AbstractC1972di.x(16, null, null));
            } catch (RemoteException unused) {
            }
            return false;
        }
        if (this.c == null) {
            com.google.android.gms.ads.internal.util.client.i.h("Ad inspector had an internal error.");
            try {
                com.google.android.gms.ads.internal.j.C.h.h("InspectorUi.shouldOpenUi", new NullPointerException("InspectorManager null"));
                interfaceC1603k0.T1(AbstractC1972di.x(16, null, null));
            } catch (RemoteException unused2) {
            }
            return false;
        }
        if (!this.e && !this.f) {
            com.google.android.gms.ads.internal.j.C.k.getClass();
            if (System.currentTimeMillis() >= this.g + ((Integer) r1.c.a(AbstractC2773w7.X8)).intValue()) {
                return true;
            }
        }
        com.google.android.gms.ads.internal.util.client.i.h("Ad inspector cannot be opened because it is already open.");
        try {
            interfaceC1603k0.T1(AbstractC1972di.x(19, null, null));
        } catch (RemoteException unused3) {
        }
        return false;
    }

    @Override // com.google.android.gms.ads.internal.overlay.j
    public final void f3() {
    }

    @Override // com.google.android.gms.ads.internal.overlay.j
    public final void v3() {
    }
}

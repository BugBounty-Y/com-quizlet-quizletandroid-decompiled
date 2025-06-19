package com.google.android.gms.internal.ads;

import com.google.android.gms.ads.internal.client.InterfaceC1582a;
import com.google.android.gms.ads.internal.client.zze;
import com.google.android.gms.ads.internal.client.zzt;

/* loaded from: classes2.dex */
public final class Lh implements com.google.android.gms.ads.admanager.a, com.google.android.gms.ads.rewarded.a, Xg, InterfaceC1582a, Bh, InterfaceC2189ih, InterfaceC2832xh, com.google.android.gms.ads.internal.overlay.j, InterfaceC2102gh, InterfaceC2447oi {
    public final C2881yn a = new C2881yn(this, 15);
    public Ln b;
    public Nn c;
    public C2411np d;
    public Np e;

    @Override // com.google.android.gms.ads.internal.overlay.j
    public final void I3() {
        C2411np c2411np = this.d;
        if (c2411np != null) {
            c2411np.I3();
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2189ih
    public final void K() {
        Ln ln = this.b;
        if (ln != null) {
            ln.K();
        }
    }

    @Override // com.google.android.gms.ads.internal.overlay.j
    public final void L2() {
        C2411np c2411np = this.d;
        if (c2411np != null) {
            c2411np.L2();
        }
    }

    @Override // com.google.android.gms.ads.internal.overlay.j
    public final void X(int i) {
        C2411np c2411np = this.d;
        if (c2411np != null) {
            c2411np.X(i);
        }
    }

    @Override // com.google.android.gms.ads.internal.overlay.j
    public final void Y3() {
    }

    @Override // com.google.android.gms.internal.ads.Xg
    public final void a() {
        Ln ln = this.b;
        if (ln != null) {
            ln.a();
        }
        Np np = this.e;
        if (np != null) {
            np.a();
        }
    }

    @Override // com.google.android.gms.internal.ads.Xg
    public final void b() {
        Ln ln = this.b;
        if (ln != null) {
            ln.b();
        }
        Np np = this.e;
        if (np != null) {
            np.b();
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2447oi
    public final void c() {
        Ln ln = this.b;
        if (ln != null) {
            ln.c();
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2447oi
    public final void c0() {
        Ln ln = this.b;
        if (ln != null) {
            ln.c0();
        }
        Nn nn = this.c;
        if (nn != null) {
            nn.c0();
        }
        Np np = this.e;
        if (np != null) {
            np.c0();
        }
        C2411np c2411np = this.d;
        if (c2411np != null) {
            c2411np.c0();
        }
    }

    @Override // com.google.android.gms.internal.ads.Bh
    public final void d(zzt zztVar) {
        Ln ln = this.b;
        if (ln != null) {
            ln.d(zztVar);
        }
        Np np = this.e;
        if (np != null) {
            np.d(zztVar);
        }
        C2411np c2411np = this.d;
        if (c2411np != null) {
            c2411np.d(zztVar);
        }
    }

    @Override // com.google.android.gms.internal.ads.Xg
    public final void f() {
        Np np = this.e;
        if (np != null) {
            np.f();
        }
    }

    @Override // com.google.android.gms.ads.internal.overlay.j
    public final void f3() {
        C2411np c2411np = this.d;
        if (c2411np != null) {
            c2411np.f3();
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2832xh
    public final void h() {
        C2411np c2411np = this.d;
        if (c2411np != null) {
            c2411np.h();
        }
    }

    @Override // com.google.android.gms.ads.rewarded.a
    public final void j() {
        Np np = this.e;
        if (np != null) {
            np.j();
        }
    }

    @Override // com.google.android.gms.ads.internal.client.InterfaceC1582a
    public final void onAdClicked() {
        Ln ln = this.b;
        if (ln != null) {
            ln.onAdClicked();
        }
        Nn nn = this.c;
        if (nn != null) {
            nn.onAdClicked();
        }
    }

    @Override // com.google.android.gms.ads.admanager.a
    public final void onAppEvent(String str, String str2) {
        Ln ln = this.b;
        if (ln != null) {
            ln.onAppEvent(str, str2);
        }
    }

    @Override // com.google.android.gms.internal.ads.Xg
    public final void q() {
        Ln ln = this.b;
        if (ln != null) {
            ln.q();
        }
        Np np = this.e;
        if (np != null) {
            np.q();
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2102gh
    public final void r(zze zzeVar) {
        Np np = this.e;
        if (np != null) {
            np.r(zzeVar);
        }
        Ln ln = this.b;
        if (ln != null) {
            ln.r(zzeVar);
        }
    }

    @Override // com.google.android.gms.internal.ads.Xg
    public final void v(BinderC1966dc binderC1966dc, String str, String str2) {
        Np np = this.e;
        if (np != null) {
            np.v(binderC1966dc, str, str2);
        }
    }

    @Override // com.google.android.gms.ads.internal.overlay.j
    public final void v3() {
    }

    @Override // com.google.android.gms.internal.ads.Xg
    public final void zze() {
        Np np = this.e;
        if (np != null) {
            np.zze();
        }
    }
}

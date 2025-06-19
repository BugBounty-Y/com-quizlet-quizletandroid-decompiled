package com.google.android.gms.internal.ads;

import android.os.Bundle;
import com.google.android.gms.ads.internal.client.InterfaceC1582a;

/* loaded from: classes2.dex */
public class Wj implements InterfaceC1582a, InterfaceC1999e9, com.google.android.gms.ads.internal.overlay.j, InterfaceC2043f9, com.google.android.gms.ads.internal.overlay.c {
    public Vg a;
    public C2746vh b;
    public C2875yh c;
    public Qh d;
    public com.google.android.gms.ads.internal.overlay.c e;

    @Override // com.google.android.gms.ads.internal.overlay.j
    public final synchronized void I3() {
        C2875yh c2875yh = this.c;
        if (c2875yh != null) {
            c2875yh.I3();
        }
    }

    @Override // com.google.android.gms.ads.internal.overlay.j
    public final synchronized void L2() {
        C2875yh c2875yh = this.c;
        if (c2875yh != null) {
            c2875yh.L2();
        }
    }

    @Override // com.google.android.gms.ads.internal.overlay.j
    public final synchronized void X(int i) {
        C2875yh c2875yh = this.c;
        if (c2875yh != null) {
            c2875yh.X(i);
        }
    }

    @Override // com.google.android.gms.ads.internal.overlay.j
    public final synchronized void Y3() {
        C2875yh c2875yh = this.c;
        if (c2875yh != null) {
            c2875yh.Y3();
        }
    }

    @Override // com.google.android.gms.ads.internal.overlay.j
    public final synchronized void f3() {
        C2875yh c2875yh = this.c;
        if (c2875yh != null) {
            c2875yh.f3();
        }
    }

    @Override // com.google.android.gms.ads.internal.overlay.c
    public final synchronized void h() {
        com.google.android.gms.ads.internal.overlay.c cVar = this.e;
        if (cVar != null) {
            cVar.h();
        }
    }

    @Override // com.google.android.gms.ads.internal.client.InterfaceC1582a
    public final synchronized void onAdClicked() {
        Vg vg = this.a;
        if (vg != null) {
            vg.onAdClicked();
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1999e9
    public final synchronized void v(Bundle bundle, String str) {
        C2746vh c2746vh = this.b;
        if (c2746vh != null) {
            c2746vh.v(bundle, str);
        }
    }

    @Override // com.google.android.gms.ads.internal.overlay.j
    public final synchronized void v3() {
        C2875yh c2875yh = this.c;
        if (c2875yh != null) {
            c2875yh.v3();
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2043f9
    public final synchronized void zzb(String str, String str2) {
        Qh qh = this.d;
        if (qh != null) {
            qh.zzb(str, str2);
        }
    }
}

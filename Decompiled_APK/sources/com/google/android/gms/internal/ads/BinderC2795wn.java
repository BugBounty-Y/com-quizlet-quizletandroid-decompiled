package com.google.android.gms.internal.ads;

import com.google.android.gms.ads.internal.client.zze;

/* renamed from: com.google.android.gms.internal.ads.wn, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public class BinderC2795wn extends AbstractBinderC1665Ba {
    public final Vg a;
    public final C2404ni b;
    public final C2146hh c;
    public final C2489ph d;
    public final C2574rh e;
    public final Qh f;
    public final C2875yh g;
    public final C2704ui h;
    public final Oh i;
    public final C2058fh j;

    public BinderC2795wn(Vg vg, C2404ni c2404ni, C2146hh c2146hh, C2489ph c2489ph, C2574rh c2574rh, Qh qh, C2875yh c2875yh, C2704ui c2704ui, Oh oh, C2058fh c2058fh) {
        this.a = vg;
        this.b = c2404ni;
        this.c = c2146hh;
        this.d = c2489ph;
        this.e = c2574rh;
        this.f = qh;
        this.g = c2875yh;
        this.h = c2704ui;
        this.i = oh;
        this.j = c2058fh;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1671Ca
    public final void B() {
        C2704ui c2704ui = this.h;
        synchronized (c2704ui) {
            try {
                if (!c2704ui.c) {
                    c2704ui.j1(new C2147hi(9, (byte) 0));
                    c2704ui.c = true;
                }
                c2704ui.j1(new C2147hi(10, (byte) 0));
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1671Ca
    public final void C0(String str) {
        j2(new zze(0, str, "undefined", null, null));
    }

    public void G() {
        this.h.j1(new C2147hi(8, (byte) 0));
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1671Ca
    public final void I0(int i, String str) {
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1671Ca
    public final void N2(int i) {
        j2(new zze(i, "", "undefined", null, null));
    }

    public void P() {
        C2704ui c2704ui = this.h;
        synchronized (c2704ui) {
            c2704ui.j1(new C2147hi(9, (byte) 0));
            c2704ui.c = true;
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1671Ca
    public final void S0(zze zzeVar) {
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1671Ca
    public final void T2(String str, String str2) {
        this.f.zzb(str, str2);
    }

    public void c() {
    }

    public void d() {
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1671Ca
    public final void e(int i) {
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1671Ca
    public final void f() {
        this.g.X(4);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1671Ca
    public final void j2(zze zzeVar) {
        this.j.a0(AbstractC1972di.t(8, zzeVar));
    }

    public void l() {
        this.c.a();
        this.i.j1(new C1927ch(21));
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1671Ca
    public final void m() {
        this.d.b();
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1671Ca
    public final void o() {
        this.g.I3();
        this.i.j1(new C1927ch(20));
    }

    public void o2(zzbwj zzbwjVar) {
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1671Ca
    public final void v() {
        this.e.s();
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1671Ca
    public final void w1(J8 j8, String str) {
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1671Ca
    public final void y() {
        this.h.j1(new C2147hi(7, (byte) 0));
    }

    public void z0(InterfaceC2312lc interfaceC2312lc) {
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1671Ca
    public final void zze() {
        this.a.onAdClicked();
        this.b.c0();
    }
}

package com.google.android.gms.internal.ads;

import com.google.android.gms.ads.internal.client.zze;

/* loaded from: classes2.dex */
public final class Rm extends AbstractBinderC1665Ba implements InterfaceC2532qh {
    public BinderC2795wn a;
    public com.bumptech.glide.manager.p b;

    @Override // com.google.android.gms.internal.ads.InterfaceC1671Ca
    public final synchronized void B() {
        BinderC2795wn binderC2795wn = this.a;
        if (binderC2795wn != null) {
            binderC2795wn.B();
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1671Ca
    public final synchronized void C0(String str) {
        BinderC2795wn binderC2795wn = this.a;
        if (binderC2795wn != null) {
            binderC2795wn.C0(str);
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1671Ca
    public final synchronized void G() {
        BinderC2795wn binderC2795wn = this.a;
        if (binderC2795wn != null) {
            binderC2795wn.G();
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1671Ca
    public final synchronized void I0(int i, String str) {
        com.bumptech.glide.manager.p pVar = this.b;
        if (pVar != null) {
            synchronized (pVar) {
                try {
                    if (!pVar.a) {
                        pVar.a = true;
                        if (str == null) {
                            str = "Error from: " + ((C2880ym) pVar.b).a + ", code: " + i;
                        }
                        pVar.j(new zze(i, str, "undefined", null, null));
                    }
                } catch (Throwable th) {
                    throw th;
                }
            }
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1671Ca
    public final synchronized void N2(int i) {
        BinderC2795wn binderC2795wn = this.a;
        if (binderC2795wn != null) {
            binderC2795wn.N2(i);
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1671Ca
    public final synchronized void P() {
        BinderC2795wn binderC2795wn = this.a;
        if (binderC2795wn != null) {
            binderC2795wn.P();
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1671Ca
    public final synchronized void S0(zze zzeVar) {
        com.bumptech.glide.manager.p pVar = this.b;
        if (pVar != null) {
            synchronized (pVar) {
                if (!pVar.a) {
                    pVar.a = true;
                    pVar.j(zzeVar);
                }
            }
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1671Ca
    public final synchronized void T2(String str, String str2) {
        BinderC2795wn binderC2795wn = this.a;
        if (binderC2795wn != null) {
            binderC2795wn.T2(str, str2);
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1671Ca
    public final synchronized void c() {
        BinderC2795wn binderC2795wn = this.a;
        if (binderC2795wn != null) {
            binderC2795wn.c();
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1671Ca
    public final synchronized void d() {
        BinderC2795wn binderC2795wn = this.a;
        if (binderC2795wn != null) {
            binderC2795wn.d();
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1671Ca
    public final synchronized void e(int i) {
        com.bumptech.glide.manager.p pVar = this.b;
        if (pVar != null) {
            pVar.h(i);
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1671Ca
    public final synchronized void f() {
        BinderC2795wn binderC2795wn = this.a;
        if (binderC2795wn != null) {
            binderC2795wn.f();
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2532qh
    public final synchronized void f0(com.bumptech.glide.manager.p pVar) {
        this.b = pVar;
    }

    public final synchronized void f4(BinderC2795wn binderC2795wn) {
        this.a = binderC2795wn;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1671Ca
    public final synchronized void j2(zze zzeVar) {
        BinderC2795wn binderC2795wn = this.a;
        if (binderC2795wn != null) {
            binderC2795wn.j2(zzeVar);
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1671Ca
    public final synchronized void l() {
        BinderC2795wn binderC2795wn = this.a;
        if (binderC2795wn != null) {
            binderC2795wn.l();
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1671Ca
    public final synchronized void m() {
        BinderC2795wn binderC2795wn = this.a;
        if (binderC2795wn != null) {
            binderC2795wn.m();
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1671Ca
    public final synchronized void o() {
        BinderC2795wn binderC2795wn = this.a;
        if (binderC2795wn != null) {
            binderC2795wn.o();
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1671Ca
    public final synchronized void o2(zzbwj zzbwjVar) {
        BinderC2795wn binderC2795wn = this.a;
        if (binderC2795wn != null) {
            binderC2795wn.o2(zzbwjVar);
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1671Ca
    public final synchronized void v() {
        try {
            BinderC2795wn binderC2795wn = this.a;
            if (binderC2795wn != null) {
                binderC2795wn.v();
            }
            com.bumptech.glide.manager.p pVar = this.b;
            if (pVar != null) {
                synchronized (pVar) {
                    ((C2313ld) pVar.c).c(null);
                }
            }
        } catch (Throwable th) {
            throw th;
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1671Ca
    public final synchronized void w1(J8 j8, String str) {
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1671Ca
    public final synchronized void y() {
        BinderC2795wn binderC2795wn = this.a;
        if (binderC2795wn != null) {
            binderC2795wn.y();
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1671Ca
    public final synchronized void z0(InterfaceC2312lc interfaceC2312lc) {
        BinderC2795wn binderC2795wn = this.a;
        if (binderC2795wn != null) {
            binderC2795wn.z0(interfaceC2312lc);
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1671Ca
    public final synchronized void zze() {
        BinderC2795wn binderC2795wn = this.a;
        if (binderC2795wn != null) {
            binderC2795wn.zze();
        }
    }
}

package com.google.android.gms.internal.ads;

/* renamed from: com.google.android.gms.internal.ads.zf, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2916zf implements Xg {
    public final Vp a;
    public final C2098gd b;

    public C2916zf(Vp vp, C2098gd c2098gd) {
        this.a = vp;
        this.b = c2098gd;
    }

    @Override // com.google.android.gms.internal.ads.Xg
    public final void a() {
        if (this.a.r0) {
            C2098gd c2098gd = this.b;
            synchronized (c2098gd.a) {
                C2054fd c2054fd = c2098gd.d;
                synchronized (c2054fd.f) {
                    c2054fd.k++;
                }
            }
        }
    }

    @Override // com.google.android.gms.internal.ads.Xg
    public final void b() {
    }

    @Override // com.google.android.gms.internal.ads.Xg
    public final void f() {
    }

    @Override // com.google.android.gms.internal.ads.Xg
    public final void q() {
    }

    @Override // com.google.android.gms.internal.ads.Xg
    public final void v(BinderC1966dc binderC1966dc, String str, String str2) {
    }

    @Override // com.google.android.gms.internal.ads.Xg
    public final void zze() {
    }
}

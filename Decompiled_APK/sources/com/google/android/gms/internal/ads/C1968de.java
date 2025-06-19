package com.google.android.gms.internal.ads;

/* renamed from: com.google.android.gms.internal.ads.de, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1968de implements InterfaceC2522qD {
    public final C1963dG a = new C1963dG();
    public long b = 15000000;
    public long c = 30000000;
    public long d = 2500000;
    public long e = 5000000;
    public int f;
    public boolean g;

    @Override // com.google.android.gms.internal.ads.InterfaceC2522qD
    public final boolean a(C2479pD c2479pD) {
        int i;
        long j = c2479pD.b;
        boolean z = true;
        char c = j > this.c ? (char) 0 : j < this.b ? (char) 2 : (char) 1;
        C1963dG c1963dG = this.a;
        synchronized (c1963dG) {
            i = c1963dG.b * 65536;
        }
        int i2 = this.f;
        if (c != 2 && (c != 1 || !this.g || i >= i2)) {
            z = false;
        }
        this.g = z;
        return z;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2522qD
    public final void b(C1917cE c1917cE) {
        this.f = 0;
        this.g = false;
        C1963dG c1963dG = this.a;
        synchronized (c1963dG) {
            c1963dG.a(0);
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2522qD
    public final void c(C2479pD c2479pD, XF[] xfArr) {
        int i;
        this.f = 0;
        for (XF xf : xfArr) {
            if (xf != null) {
                int i2 = this.f;
                int i3 = xf.a().c;
                if (i3 == 0) {
                    i = 144310272;
                } else if (i3 == 1) {
                    i = 13107200;
                } else if (i3 != 2) {
                    i = 131072;
                    if (i3 != 3 && i3 != 5 && i3 != 6) {
                        throw new IllegalArgumentException();
                    }
                } else {
                    i = 131072000;
                }
                this.f = i2 + i;
            }
        }
        this.a.a(this.f);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2522qD
    public final boolean d(C2479pD c2479pD) {
        long j = c2479pD.d ? this.e : this.d;
        return j <= 0 || c2479pD.b >= j;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2522qD
    public final void e(C1917cE c1917cE) {
        this.f = 0;
        this.g = false;
        C1963dG c1963dG = this.a;
        synchronized (c1963dG) {
            c1963dG.a(0);
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2522qD
    public final void f(C1917cE c1917cE) {
        this.f = 0;
        this.g = false;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2522qD
    public final C1963dG n() {
        return this.a;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2522qD
    public final long zzb() {
        return 0L;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2522qD
    public final /* synthetic */ boolean zzi() {
        AbstractC2096gb.J("LoadControl", "shouldContinuePreloading needs to be implemented when playlist preloading is enabled");
        return false;
    }
}

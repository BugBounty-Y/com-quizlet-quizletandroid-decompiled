package com.google.android.gms.internal.ads;

import androidx.compose.foundation.lazy.layout.C0429a;
import java.util.List;

/* renamed from: com.google.android.gms.internal.ads.j0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2208j0 implements U {
    public final int a;
    public final int b;
    public final String c;
    public int d;
    public int e;
    public C2695uF f;
    public InterfaceC2380n0 g;

    public C2208j0(int i, int i2, String str) {
        this.a = i;
        this.b = i2;
        this.c = str;
    }

    @Override // com.google.android.gms.internal.ads.U
    public final boolean d(V v) {
        int i = this.b;
        int i2 = this.a;
        AbstractC1795We.L((i2 == -1 || i == -1) ? false : true);
        Kn kn = new Kn(i);
        ((P) v).k(kn.a, 0, i, false);
        return kn.D() == i2;
    }

    @Override // com.google.android.gms.internal.ads.U
    public final void e(W w) {
        C2695uF c2695uF = (C2695uF) w;
        this.f = c2695uF;
        InterfaceC2380n0 interfaceC2380n0Q = c2695uF.q(1024, 4);
        this.g = interfaceC2380n0Q;
        EF ef = new EF();
        String str = this.c;
        ef.a(str);
        ef.d(str);
        interfaceC2380n0Q.a(new C1832aG(ef));
        this.f.n();
        this.f.p(new C2251k0());
        this.e = 1;
    }

    @Override // com.google.android.gms.internal.ads.U
    public final int f(V v, C0429a c0429a) {
        int i = this.e;
        if (i != 1) {
            if (i == 2) {
                return -1;
            }
            throw new IllegalStateException();
        }
        InterfaceC2380n0 interfaceC2380n0 = this.g;
        interfaceC2380n0.getClass();
        int iD = interfaceC2380n0.d(v, 1024, true);
        if (iD != -1) {
            this.d += iD;
            return 0;
        }
        this.e = 2;
        this.g.f(0L, 1, this.d, 0, null);
        this.d = 0;
        return 0;
    }

    @Override // com.google.android.gms.internal.ads.U
    public final void h(long j, long j2) {
        if (j == 0 || this.e == 1) {
            this.e = 1;
            this.d = 0;
        }
    }

    @Override // com.google.android.gms.internal.ads.U
    public final List j() {
        C2244ju c2244ju = AbstractC2330lu.b;
        return Bu.e;
    }
}

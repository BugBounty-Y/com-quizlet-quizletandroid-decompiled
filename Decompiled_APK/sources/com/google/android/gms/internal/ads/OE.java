package com.google.android.gms.internal.ads;

/* loaded from: classes2.dex */
public final class OE implements AF {
    public final AF a;
    public boolean b;
    public final /* synthetic */ PE c;

    public OE(PE pe, AF af) {
        this.c = pe;
        this.a = af;
    }

    @Override // com.google.android.gms.internal.ads.AF
    public final int a(long j) {
        if (this.c.n()) {
            return -3;
        }
        return this.a.a(j);
    }

    @Override // com.google.android.gms.internal.ads.AF
    public final int b(Ps ps, MC mc, int i) {
        PE pe = this.c;
        if (pe.n()) {
            return -3;
        }
        if (this.b) {
            mc.b = 4;
            return -4;
        }
        long jB = pe.b();
        int iB = this.a.b(ps, mc, i);
        if (iB != -5) {
            long j = pe.e;
            if (j == Long.MIN_VALUE || ((iB != -4 || mc.g < j) && !(iB == -3 && jB == Long.MIN_VALUE && !mc.f))) {
                return iB;
            }
            mc.v();
            mc.b = 4;
            this.b = true;
            return -4;
        }
        C1832aG c1832aG = (C1832aG) ps.a;
        c1832aG.getClass();
        int i2 = c1832aG.G;
        int i3 = c1832aG.F;
        if (i3 == 0) {
            if (i2 == 0) {
                return -5;
            }
            i3 = 0;
        }
        int i4 = pe.e == Long.MIN_VALUE ? i2 : 0;
        EF ef = new EF(c1832aG);
        ef.E = i3;
        ef.F = i4;
        ps.a = new C1832aG(ef);
        return -5;
    }

    @Override // com.google.android.gms.internal.ads.AF
    public final void j() {
        this.a.j();
    }

    @Override // com.google.android.gms.internal.ads.AF
    public final boolean zze() {
        return !this.c.n() && this.a.zze();
    }
}

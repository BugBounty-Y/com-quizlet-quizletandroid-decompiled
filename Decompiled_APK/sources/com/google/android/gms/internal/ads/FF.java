package com.google.android.gms.internal.ads;

/* loaded from: classes2.dex */
public final class FF implements AF {
    public final AF a;
    public final long b;

    public FF(AF af, long j) {
        this.a = af;
        this.b = j;
    }

    @Override // com.google.android.gms.internal.ads.AF
    public final int a(long j) {
        return this.a.a(j - this.b);
    }

    @Override // com.google.android.gms.internal.ads.AF
    public final int b(Ps ps, MC mc, int i) {
        int iB = this.a.b(ps, mc, i);
        if (iB != -4) {
            return iB;
        }
        mc.g += this.b;
        return -4;
    }

    @Override // com.google.android.gms.internal.ads.AF
    public final void j() {
        this.a.j();
    }

    @Override // com.google.android.gms.internal.ads.AF
    public final boolean zze() {
        return this.a.zze();
    }
}

package com.google.android.gms.internal.ads;

/* loaded from: classes2.dex */
public final class MF extends TF implements Comparable {
    public final int e;
    public final int f;

    public MF(int i, J9 j9, int i2, PF pf, int i3) {
        int i4;
        super(i, j9, i2);
        this.e = AbstractC2457os.k(i3, pf.y) ? 1 : 0;
        C1832aG c1832aG = this.d;
        int i5 = c1832aG.t;
        int i6 = -1;
        if (i5 != -1 && (i4 = c1832aG.u) != -1) {
            i6 = i5 * i4;
        }
        this.f = i6;
    }

    @Override // com.google.android.gms.internal.ads.TF
    public final int a() {
        return this.e;
    }

    @Override // com.google.android.gms.internal.ads.TF
    public final /* bridge */ /* synthetic */ boolean b(TF tf) {
        return false;
    }

    @Override // java.lang.Comparable
    public final int compareTo(Object obj) {
        return Integer.compare(this.f, ((MF) obj).f);
    }
}

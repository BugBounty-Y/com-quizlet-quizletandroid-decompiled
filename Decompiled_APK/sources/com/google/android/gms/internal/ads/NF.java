package com.google.android.gms.internal.ads;

/* loaded from: classes2.dex */
public final class NF implements Comparable {
    public final boolean a;
    public final boolean b;

    public NF(C1832aG c1832aG, int i) {
        this.a = 1 == (c1832aG.e & 1);
        this.b = AbstractC2457os.k(i, false);
    }

    @Override // java.lang.Comparable
    public final int compareTo(Object obj) {
        NF nf = (NF) obj;
        return AbstractC1983du.a.d(this.b, nf.b).d(this.a, nf.a).a();
    }
}

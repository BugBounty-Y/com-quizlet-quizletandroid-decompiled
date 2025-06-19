package com.google.android.gms.internal.ads;

import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;

/* loaded from: classes2.dex */
public final class RF extends TF implements Comparable {
    public final int e;
    public final boolean f;
    public final boolean g;
    public final boolean h;
    public final int i;
    public final int j;
    public final int k;
    public final int l;
    public final boolean m;

    public RF(int i, J9 j9, int i2, PF pf, int i3, String str, String str2) {
        int iBitCount;
        int iA;
        super(i, j9, i2);
        int i4 = 0;
        this.f = AbstractC2457os.k(i3, false);
        int i5 = this.d.e;
        pf.getClass();
        this.g = 1 == (i5 & 1);
        this.h = (i5 & 2) != 0;
        Bu bu = pf.p;
        Bu buS = str2 != null ? AbstractC2330lu.s(str2) : bu.isEmpty() ? AbstractC2330lu.s("") : bu;
        int i6 = 0;
        while (true) {
            int i7 = buS.d;
            iBitCount = SubsamplingScaleImageView.TILE_SIZE_AUTO;
            if (i6 >= i7) {
                iA = 0;
                i6 = Integer.MAX_VALUE;
                break;
            } else {
                iA = VF.a(this.d, (String) buS.get(i6), false);
                if (iA > 0) {
                    break;
                } else {
                    i6++;
                }
            }
        }
        this.i = i6;
        this.j = iA;
        int i8 = str2 != null ? 1088 : 0;
        int i9 = this.d.f;
        iBitCount = (i9 == 0 || i9 != i8) ? Integer.bitCount(i8 & i9) : iBitCount;
        this.k = iBitCount;
        this.m = (1088 & this.d.f) != 0;
        int iA2 = VF.a(this.d, str, VF.b(str) == null);
        this.l = iA2;
        boolean z = iA > 0 || (bu.isEmpty() && iBitCount > 0) || this.g || (this.h && iA2 > 0);
        if (AbstractC2457os.k(i3, pf.y) && z) {
            i4 = 1;
        }
        this.e = i4;
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
    /* renamed from: c, reason: merged with bridge method [inline-methods] */
    public final int compareTo(RF rf) {
        AbstractC1983du abstractC1983duD = AbstractC1983du.a.d(this.f, rf.f);
        Integer numValueOf = Integer.valueOf(this.i);
        Integer numValueOf2 = Integer.valueOf(rf.i);
        C2931zu c2931zu = C2931zu.c;
        AbstractC1983du abstractC1983duC = abstractC1983duD.c(numValueOf, numValueOf2, c2931zu);
        int i = this.j;
        AbstractC1983du abstractC1983duB = abstractC1983duC.b(i, rf.j);
        int i2 = this.k;
        AbstractC1983du abstractC1983duD2 = abstractC1983duB.b(i2, rf.k).d(this.g, rf.g);
        Boolean boolValueOf = Boolean.valueOf(this.h);
        Boolean boolValueOf2 = Boolean.valueOf(rf.h);
        if (i == 0) {
            c2931zu = C2931zu.b;
        }
        AbstractC1983du abstractC1983duB2 = abstractC1983duD2.c(boolValueOf, boolValueOf2, c2931zu).b(this.l, rf.l);
        if (i2 == 0) {
            abstractC1983duB2 = abstractC1983duB2.e(this.m, rf.m);
        }
        return abstractC1983duB2.a();
    }
}

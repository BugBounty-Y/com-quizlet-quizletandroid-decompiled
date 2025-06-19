package com.google.android.gms.internal.ads;

import android.text.TextUtils;
import java.util.Comparator;
import java.util.Objects;

/* loaded from: classes2.dex */
public final class LF extends TF implements Comparable {
    public final int e;
    public final boolean f;
    public final String g;
    public final PF h;
    public final boolean i;
    public final int j;
    public final int k;
    public final int l;
    public final boolean m;
    public final int n;
    public final int o;
    public final boolean p;
    public final int q;
    public final int r;
    public final int s;
    public final int t;
    public final boolean u;
    public final boolean v;
    public final boolean w;

    /* JADX WARN: Removed duplicated region for block: B:31:0x0071  */
    /* JADX WARN: Removed duplicated region for block: B:48:0x00a5  */
    /* JADX WARN: Removed duplicated region for block: B:50:0x00a8 A[ADDED_TO_REGION] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public LF(int r9, com.google.android.gms.internal.ads.J9 r10, int r11, com.google.android.gms.internal.ads.PF r12, int r13, boolean r14, com.google.android.gms.internal.ads.KF r15) {
        /*
            Method dump skipped, instructions count: 375
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.LF.<init>(int, com.google.android.gms.internal.ads.J9, int, com.google.android.gms.internal.ads.PF, int, boolean, com.google.android.gms.internal.ads.KF):void");
    }

    @Override // com.google.android.gms.internal.ads.TF
    public final int a() {
        return this.e;
    }

    @Override // com.google.android.gms.internal.ads.TF
    public final /* bridge */ /* synthetic */ boolean b(TF tf) {
        String str;
        int i;
        LF lf = (LF) tf;
        this.h.getClass();
        C1832aG c1832aG = this.d;
        int i2 = c1832aG.C;
        if (i2 == -1) {
            return false;
        }
        C1832aG c1832aG2 = lf.d;
        return i2 == c1832aG2.C && (str = c1832aG.m) != null && TextUtils.equals(str, c1832aG2.m) && (i = c1832aG.D) != -1 && i == c1832aG2.D && this.u == lf.u && this.v == lf.v;
    }

    @Override // java.lang.Comparable
    /* renamed from: c, reason: merged with bridge method [inline-methods] */
    public final int compareTo(LF lf) {
        Comparator iu = VF.i;
        boolean z = this.i;
        boolean z2 = this.f;
        if (!z2 || !z) {
            iu = new Iu();
        }
        AbstractC1983du abstractC1983duD = AbstractC1983du.a.d(z, lf.i);
        Integer numValueOf = Integer.valueOf(this.k);
        Integer numValueOf2 = Integer.valueOf(lf.k);
        C2931zu c2931zu = C2931zu.c;
        AbstractC1983du abstractC1983duC = abstractC1983duD.c(numValueOf, numValueOf2, c2931zu).b(this.j, lf.j).b(this.l, lf.l).d(this.p, lf.p).d(this.m, lf.m).c(Integer.valueOf(this.n), Integer.valueOf(lf.n), c2931zu).b(this.o, lf.o).d(z2, lf.f).c(Integer.valueOf(this.t), Integer.valueOf(lf.t), c2931zu);
        this.h.getClass();
        AbstractC1983du abstractC1983duC2 = abstractC1983duC.d(this.u, lf.u).d(this.v, lf.v).d(this.w, lf.w).c(Integer.valueOf(this.q), Integer.valueOf(lf.q), iu).c(Integer.valueOf(this.r), Integer.valueOf(lf.r), iu);
        if (Objects.equals(this.g, lf.g)) {
            abstractC1983duC2 = abstractC1983duC2.c(Integer.valueOf(this.s), Integer.valueOf(lf.s), iu);
        }
        return abstractC1983duC2.a();
    }
}

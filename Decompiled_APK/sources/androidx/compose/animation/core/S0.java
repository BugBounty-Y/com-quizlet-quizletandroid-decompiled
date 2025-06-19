package androidx.compose.animation.core;

import com.google.android.gms.internal.ads.C1832aG;

/* loaded from: classes.dex */
public final class S0 implements N0 {
    public final int a;
    public final long b;
    public final long c;
    public final Object d;

    public S0(int i, C1832aG c1832aG, long j, long j2) {
        this.a = i;
        this.d = c1832aG;
        this.b = j;
        this.c = j2;
    }

    @Override // androidx.compose.animation.core.N0
    public boolean a() {
        return true;
    }

    @Override // androidx.compose.animation.core.N0
    public long b(AbstractC0267t abstractC0267t, AbstractC0267t abstractC0267t2, AbstractC0267t abstractC0267t3) {
        return Long.MAX_VALUE;
    }

    public long c(long j) {
        long j2 = j + this.c;
        if (j2 <= 0) {
            return 0L;
        }
        long j3 = this.b;
        long j4 = j2 / j3;
        return (this.a == 1 || j4 % ((long) 2) == 0) ? j2 - (j4 * j3) : ((j4 + 1) * j3) - j2;
    }

    public AbstractC0267t d(long j, AbstractC0267t abstractC0267t, AbstractC0267t abstractC0267t2, AbstractC0267t abstractC0267t3) {
        long j2 = this.c;
        long j3 = j + j2;
        long j4 = this.b;
        return j3 > j4 ? ((P0) this.d).j(j4 - j2, abstractC0267t, abstractC0267t3, abstractC0267t2) : abstractC0267t2;
    }

    @Override // androidx.compose.animation.core.N0
    public AbstractC0267t j(long j, AbstractC0267t abstractC0267t, AbstractC0267t abstractC0267t2, AbstractC0267t abstractC0267t3) {
        return ((P0) this.d).j(c(j), abstractC0267t, abstractC0267t2, d(j, abstractC0267t, abstractC0267t3, abstractC0267t2));
    }

    @Override // androidx.compose.animation.core.N0
    public AbstractC0267t t(long j, AbstractC0267t abstractC0267t, AbstractC0267t abstractC0267t2, AbstractC0267t abstractC0267t3) {
        return ((P0) this.d).t(c(j), abstractC0267t, abstractC0267t2, d(j, abstractC0267t, abstractC0267t3, abstractC0267t2));
    }

    public S0(P0 p0, int i, long j) {
        this.d = p0;
        this.a = i;
        this.b = (p0.u() + p0.m()) * 1000000;
        this.c = j * 1000000;
    }
}

package androidx.compose.animation.core;

import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.compose.animation.core.n0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0257n0 implements N0 {
    public final N0 a;
    public final long b;

    public C0257n0(N0 n0, long j) {
        this.a = n0;
        this.b = j;
    }

    @Override // androidx.compose.animation.core.N0
    public final boolean a() {
        return this.a.a();
    }

    @Override // androidx.compose.animation.core.N0
    public final long b(AbstractC0267t abstractC0267t, AbstractC0267t abstractC0267t2, AbstractC0267t abstractC0267t3) {
        return this.a.b(abstractC0267t, abstractC0267t2, abstractC0267t3) + this.b;
    }

    public final boolean equals(Object obj) {
        if (!(obj instanceof C0257n0)) {
            return false;
        }
        C0257n0 c0257n0 = (C0257n0) obj;
        return c0257n0.b == this.b && Intrinsics.b(c0257n0.a, this.a);
    }

    public final int hashCode() {
        return Long.hashCode(this.b) + (this.a.hashCode() * 31);
    }

    @Override // androidx.compose.animation.core.N0
    public final AbstractC0267t j(long j, AbstractC0267t abstractC0267t, AbstractC0267t abstractC0267t2, AbstractC0267t abstractC0267t3) {
        long j2 = this.b;
        return j < j2 ? abstractC0267t3 : this.a.j(j - j2, abstractC0267t, abstractC0267t2, abstractC0267t3);
    }

    @Override // androidx.compose.animation.core.N0
    public final AbstractC0267t t(long j, AbstractC0267t abstractC0267t, AbstractC0267t abstractC0267t2, AbstractC0267t abstractC0267t3) {
        long j2 = this.b;
        return j < j2 ? abstractC0267t : this.a.t(j - j2, abstractC0267t, abstractC0267t2, abstractC0267t3);
    }
}

package kotlinx.coroutines.flow;

import androidx.paging.J0;
import kotlin.collections.CollectionsKt;

/* loaded from: classes3.dex */
public final class p0 implements i0 {
    public final long a;

    public p0(long j) {
        this.a = j;
        if (j < 0) {
            throw new IllegalArgumentException(androidx.compose.animation.d0.o(j, "stopTimeout(", " ms) cannot be negative").toString());
        }
    }

    @Override // kotlinx.coroutines.flow.i0
    public final InterfaceC4992i a(kotlinx.coroutines.flow.internal.H h) {
        n0 n0Var = new n0(this, null);
        int i = G.a;
        return e0.m(new J0(new kotlinx.coroutines.flow.internal.m(n0Var, h, kotlin.coroutines.n.a, -2, kotlinx.coroutines.channels.a.a), new o0(2, null), 3));
    }

    public final boolean equals(Object obj) {
        if (obj instanceof p0) {
            return this.a == ((p0) obj).a;
        }
        return false;
    }

    public final int hashCode() {
        return Long.hashCode(Long.MAX_VALUE) + (Long.hashCode(this.a) * 31);
    }

    public final String toString() {
        kotlin.collections.builders.d dVar = new kotlin.collections.builders.d(2);
        long j = this.a;
        if (j > 0) {
            dVar.add("stopTimeout=" + j + "ms");
        }
        return androidx.compose.animation.d0.r(new StringBuilder("SharingStarted.WhileSubscribed("), CollectionsKt.S(kotlin.collections.A.a(dVar), null, null, null, null, 63), ')');
    }
}

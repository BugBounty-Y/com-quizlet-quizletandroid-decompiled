package androidx.compose.foundation.layout;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class O implements R0 {
    public final R0 a;
    public final R0 b;

    public O(R0 r0, R0 r02) {
        this.a = r0;
        this.b = r02;
    }

    @Override // androidx.compose.foundation.layout.R0
    public final int a(androidx.compose.ui.unit.b bVar) {
        int iA = this.a.a(bVar) - this.b.a(bVar);
        if (iA < 0) {
            return 0;
        }
        return iA;
    }

    @Override // androidx.compose.foundation.layout.R0
    public final int b(androidx.compose.ui.unit.b bVar, androidx.compose.ui.unit.k kVar) {
        int iB = this.a.b(bVar, kVar) - this.b.b(bVar, kVar);
        if (iB < 0) {
            return 0;
        }
        return iB;
    }

    @Override // androidx.compose.foundation.layout.R0
    public final int c(androidx.compose.ui.unit.b bVar) {
        int iC = this.a.c(bVar) - this.b.c(bVar);
        if (iC < 0) {
            return 0;
        }
        return iC;
    }

    @Override // androidx.compose.foundation.layout.R0
    public final int d(androidx.compose.ui.unit.b bVar, androidx.compose.ui.unit.k kVar) {
        int iD = this.a.d(bVar, kVar) - this.b.d(bVar, kVar);
        if (iD < 0) {
            return 0;
        }
        return iD;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof O)) {
            return false;
        }
        O o = (O) obj;
        return Intrinsics.b(o.a, this.a) && Intrinsics.b(o.b, this.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "(" + this.a + " - " + this.b + ')';
    }
}

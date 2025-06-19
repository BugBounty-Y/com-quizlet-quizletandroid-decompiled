package androidx.compose.foundation.layout;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class M0 implements R0 {
    public final R0 a;
    public final R0 b;

    public M0(R0 r0, R0 r02) {
        this.a = r0;
        this.b = r02;
    }

    @Override // androidx.compose.foundation.layout.R0
    public final int a(androidx.compose.ui.unit.b bVar) {
        return Math.max(this.a.a(bVar), this.b.a(bVar));
    }

    @Override // androidx.compose.foundation.layout.R0
    public final int b(androidx.compose.ui.unit.b bVar, androidx.compose.ui.unit.k kVar) {
        return Math.max(this.a.b(bVar, kVar), this.b.b(bVar, kVar));
    }

    @Override // androidx.compose.foundation.layout.R0
    public final int c(androidx.compose.ui.unit.b bVar) {
        return Math.max(this.a.c(bVar), this.b.c(bVar));
    }

    @Override // androidx.compose.foundation.layout.R0
    public final int d(androidx.compose.ui.unit.b bVar, androidx.compose.ui.unit.k kVar) {
        return Math.max(this.a.d(bVar, kVar), this.b.d(bVar, kVar));
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof M0)) {
            return false;
        }
        M0 m0 = (M0) obj;
        return Intrinsics.b(m0.a, this.a) && Intrinsics.b(m0.b, this.b);
    }

    public final int hashCode() {
        return (this.b.hashCode() * 31) + this.a.hashCode();
    }

    public final String toString() {
        return "(" + this.a + " ∪ " + this.b + ')';
    }
}

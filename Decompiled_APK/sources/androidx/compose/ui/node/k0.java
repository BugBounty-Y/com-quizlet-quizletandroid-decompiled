package androidx.compose.ui.node;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class k0 implements h0 {
    public final androidx.compose.ui.layout.L a;
    public final O b;

    public k0(androidx.compose.ui.layout.L l, O o) {
        this.a = l;
        this.b = o;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof k0)) {
            return false;
        }
        k0 k0Var = (k0) obj;
        return Intrinsics.b(this.a, k0Var.a) && Intrinsics.b(this.b, k0Var.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "PlaceableResult(result=" + this.a + ", placeable=" + this.b + ')';
    }

    @Override // androidx.compose.ui.node.h0
    public final boolean u() {
        return this.b.C0().k();
    }
}

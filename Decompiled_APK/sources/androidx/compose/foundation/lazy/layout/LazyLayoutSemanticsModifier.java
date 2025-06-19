package androidx.compose.foundation.lazy.layout;

import androidx.compose.foundation.gestures.EnumC0320d0;
import androidx.compose.ui.node.AbstractC0910f;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes.dex */
final class LazyLayoutSemanticsModifier extends androidx.compose.ui.node.T {
    public final kotlin.reflect.k b;
    public final e0 c;
    public final EnumC0320d0 d;
    public final boolean e;

    public LazyLayoutSemanticsModifier(kotlin.reflect.k kVar, e0 e0Var, EnumC0320d0 enumC0320d0, boolean z) {
        this.b = kVar;
        this.c = e0Var;
        this.d = enumC0320d0;
        this.e = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof LazyLayoutSemanticsModifier)) {
            return false;
        }
        LazyLayoutSemanticsModifier lazyLayoutSemanticsModifier = (LazyLayoutSemanticsModifier) obj;
        return this.b == lazyLayoutSemanticsModifier.b && Intrinsics.b(this.c, lazyLayoutSemanticsModifier.c) && this.d == lazyLayoutSemanticsModifier.d && this.e == lazyLayoutSemanticsModifier.e;
    }

    public final int hashCode() {
        return Boolean.hashCode(false) + androidx.compose.animation.d0.g((this.d.hashCode() + ((this.c.hashCode() + (this.b.hashCode() * 31)) * 31)) * 31, 31, this.e);
    }

    @Override // androidx.compose.ui.node.T
    public final androidx.compose.ui.p l() {
        EnumC0320d0 enumC0320d0 = this.d;
        return new i0(this.b, this.c, enumC0320d0, this.e);
    }

    @Override // androidx.compose.ui.node.T
    public final void n(androidx.compose.ui.p pVar) {
        i0 i0Var = (i0) pVar;
        i0Var.n = this.b;
        i0Var.o = this.c;
        EnumC0320d0 enumC0320d0 = i0Var.p;
        EnumC0320d0 enumC0320d02 = this.d;
        if (enumC0320d0 != enumC0320d02) {
            i0Var.p = enumC0320d02;
            AbstractC0910f.p(i0Var);
        }
        boolean z = i0Var.q;
        boolean z2 = this.e;
        if (z == z2) {
            return;
        }
        i0Var.q = z2;
        i0Var.M0();
        AbstractC0910f.p(i0Var);
    }
}

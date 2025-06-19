package androidx.compose.ui.graphics;

import androidx.compose.ui.node.AbstractC0910f;
import kotlin.Metadata;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes.dex */
final class BlockGraphicsLayerElement extends androidx.compose.ui.node.T {
    public final Function1 b;

    public BlockGraphicsLayerElement(Function1 function1) {
        this.b = function1;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof BlockGraphicsLayerElement) && Intrinsics.b(this.b, ((BlockGraphicsLayerElement) obj).b);
    }

    public final int hashCode() {
        return this.b.hashCode();
    }

    @Override // androidx.compose.ui.node.T
    public final androidx.compose.ui.p l() {
        return new C0855o(this.b);
    }

    @Override // androidx.compose.ui.node.T
    public final void n(androidx.compose.ui.p pVar) {
        C0855o c0855o = (C0855o) pVar;
        c0855o.n = this.b;
        androidx.compose.ui.node.a0 a0Var = AbstractC0910f.t(c0855o, 2).m;
        if (a0Var != null) {
            a0Var.r1(c0855o.n, true);
        }
    }

    public final String toString() {
        return "BlockGraphicsLayerElement(block=" + this.b + ')';
    }
}

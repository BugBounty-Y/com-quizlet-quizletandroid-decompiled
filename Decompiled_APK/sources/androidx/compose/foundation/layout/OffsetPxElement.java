package androidx.compose.foundation.layout;

import kotlin.Metadata;
import kotlin.jvm.functions.Function1;

@Metadata
/* loaded from: classes.dex */
final class OffsetPxElement extends androidx.compose.ui.node.T {
    public final Function1 b;

    public OffsetPxElement(Function1 function1, androidx.compose.animation.U u) {
        this.b = function1;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        OffsetPxElement offsetPxElement = obj instanceof OffsetPxElement ? (OffsetPxElement) obj : null;
        return offsetPxElement != null && this.b == offsetPxElement.b;
    }

    public final int hashCode() {
        return Boolean.hashCode(true) + (this.b.hashCode() * 31);
    }

    @Override // androidx.compose.ui.node.T
    public final androidx.compose.ui.p l() {
        x0 x0Var = new x0();
        x0Var.n = this.b;
        x0Var.o = true;
        return x0Var;
    }

    @Override // androidx.compose.ui.node.T
    public final void n(androidx.compose.ui.p pVar) {
        x0 x0Var = (x0) pVar;
        x0Var.n = this.b;
        x0Var.o = true;
    }

    public final String toString() {
        return "OffsetPxModifier(offset=" + this.b + ", rtlAware=true)";
    }
}

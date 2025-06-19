package androidx.compose.foundation.layout;

import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes.dex */
final class PaddingValuesElement extends androidx.compose.ui.node.T {
    public final z0 b;

    public PaddingValuesElement(z0 z0Var, C0406q c0406q) {
        this.b = z0Var;
    }

    public final boolean equals(Object obj) {
        PaddingValuesElement paddingValuesElement = obj instanceof PaddingValuesElement ? (PaddingValuesElement) obj : null;
        if (paddingValuesElement == null) {
            return false;
        }
        return Intrinsics.b(this.b, paddingValuesElement.b);
    }

    public final int hashCode() {
        return this.b.hashCode();
    }

    @Override // androidx.compose.ui.node.T
    public final androidx.compose.ui.p l() {
        B0 b0 = new B0();
        b0.n = this.b;
        return b0;
    }

    @Override // androidx.compose.ui.node.T
    public final void n(androidx.compose.ui.p pVar) {
        ((B0) pVar).n = this.b;
    }
}

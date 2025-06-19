package androidx.compose.foundation.layout;

import kotlin.Metadata;

@Metadata
/* loaded from: classes.dex */
final class AspectRatioElement extends androidx.compose.ui.node.T {
    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if ((obj instanceof AspectRatioElement ? (AspectRatioElement) obj : null) == null) {
            return false;
        }
        ((AspectRatioElement) obj).getClass();
        return true;
    }

    public final int hashCode() {
        return Boolean.hashCode(false) + (Float.hashCode(1.0f) * 31);
    }

    @Override // androidx.compose.ui.node.T
    public final androidx.compose.ui.p l() {
        C0400n c0400n = new C0400n();
        c0400n.n = 1.0f;
        return c0400n;
    }

    @Override // androidx.compose.ui.node.T
    public final void n(androidx.compose.ui.p pVar) {
        ((C0400n) pVar).n = 1.0f;
    }
}

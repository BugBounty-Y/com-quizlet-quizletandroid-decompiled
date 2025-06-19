package androidx.compose.foundation.layout;

import androidx.camera.camera2.internal.AbstractC0147y;
import kotlin.Metadata;

@Metadata
/* loaded from: classes.dex */
final class IntrinsicHeightElement extends androidx.compose.ui.node.T {
    public final int b;

    public IntrinsicHeightElement(int i) {
        this.b = i;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        IntrinsicHeightElement intrinsicHeightElement = obj instanceof IntrinsicHeightElement ? (IntrinsicHeightElement) obj : null;
        return intrinsicHeightElement != null && this.b == intrinsicHeightElement.b;
    }

    public final int hashCode() {
        return Boolean.hashCode(true) + (AbstractC0147y.k(this.b) * 31);
    }

    @Override // androidx.compose.ui.node.T
    public final androidx.compose.ui.p l() {
        C0410s0 c0410s0 = new C0410s0(1);
        c0410s0.o = this.b;
        c0410s0.p = true;
        return c0410s0;
    }

    @Override // androidx.compose.ui.node.T
    public final void n(androidx.compose.ui.p pVar) {
        C0410s0 c0410s0 = (C0410s0) pVar;
        c0410s0.o = this.b;
        c0410s0.p = true;
    }
}

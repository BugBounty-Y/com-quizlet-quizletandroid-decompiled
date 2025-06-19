package androidx.compose.foundation.layout;

import androidx.camera.camera2.internal.AbstractC0147y;
import kotlin.Metadata;

@Metadata
/* loaded from: classes.dex */
final class IntrinsicWidthElement extends androidx.compose.ui.node.T {
    public final int b;

    public IntrinsicWidthElement(int i) {
        this.b = i;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        IntrinsicWidthElement intrinsicWidthElement = obj instanceof IntrinsicWidthElement ? (IntrinsicWidthElement) obj : null;
        return intrinsicWidthElement != null && this.b == intrinsicWidthElement.b;
    }

    public final int hashCode() {
        return Boolean.hashCode(true) + (AbstractC0147y.k(this.b) * 31);
    }

    @Override // androidx.compose.ui.node.T
    public final androidx.compose.ui.p l() {
        C0412t0 c0412t0 = new C0412t0(1);
        c0412t0.o = this.b;
        c0412t0.p = true;
        return c0412t0;
    }

    @Override // androidx.compose.ui.node.T
    public final void n(androidx.compose.ui.p pVar) {
        C0412t0 c0412t0 = (C0412t0) pVar;
        c0412t0.o = this.b;
        c0412t0.p = true;
    }
}

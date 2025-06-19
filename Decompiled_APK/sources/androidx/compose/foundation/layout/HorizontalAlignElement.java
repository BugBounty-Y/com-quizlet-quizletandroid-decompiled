package androidx.compose.foundation.layout;

import kotlin.Metadata;

@Metadata
/* loaded from: classes.dex */
public final class HorizontalAlignElement extends androidx.compose.ui.node.T {
    public final androidx.compose.ui.g b;

    public HorizontalAlignElement(androidx.compose.ui.g gVar) {
        this.b = gVar;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        HorizontalAlignElement horizontalAlignElement = obj instanceof HorizontalAlignElement ? (HorizontalAlignElement) obj : null;
        if (horizontalAlignElement == null) {
            return false;
        }
        return this.b.equals(horizontalAlignElement.b);
    }

    public final int hashCode() {
        return Float.hashCode(this.b.a);
    }

    @Override // androidx.compose.ui.node.T
    public final androidx.compose.ui.p l() {
        C0401n0 c0401n0 = new C0401n0();
        c0401n0.n = this.b;
        return c0401n0;
    }

    @Override // androidx.compose.ui.node.T
    public final void n(androidx.compose.ui.p pVar) {
        ((C0401n0) pVar).n = this.b;
    }
}

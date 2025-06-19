package androidx.compose.foundation.layout;

import kotlin.Metadata;

@Metadata
/* loaded from: classes.dex */
public final class VerticalAlignElement extends androidx.compose.ui.node.T {
    public final androidx.compose.ui.h b;

    public VerticalAlignElement(androidx.compose.ui.h hVar) {
        this.b = hVar;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        VerticalAlignElement verticalAlignElement = obj instanceof VerticalAlignElement ? (VerticalAlignElement) obj : null;
        if (verticalAlignElement == null) {
            return false;
        }
        return this.b.equals(verticalAlignElement.b);
    }

    public final int hashCode() {
        return Float.hashCode(this.b.a);
    }

    @Override // androidx.compose.ui.node.T
    public final androidx.compose.ui.p l() {
        Q0 q0 = new Q0();
        q0.n = this.b;
        return q0;
    }

    @Override // androidx.compose.ui.node.T
    public final void n(androidx.compose.ui.p pVar) {
        ((Q0) pVar).n = this.b;
    }
}

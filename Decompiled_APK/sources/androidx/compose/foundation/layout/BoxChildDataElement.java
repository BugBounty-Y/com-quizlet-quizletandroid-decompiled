package androidx.compose.foundation.layout;

import kotlin.Metadata;

@Metadata
/* loaded from: classes.dex */
final class BoxChildDataElement extends androidx.compose.ui.node.T {
    public final androidx.compose.ui.i b;
    public final boolean c;

    public BoxChildDataElement(androidx.compose.ui.i iVar, boolean z) {
        this.b = iVar;
        this.c = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        BoxChildDataElement boxChildDataElement = obj instanceof BoxChildDataElement ? (BoxChildDataElement) obj : null;
        return boxChildDataElement != null && this.b.equals(boxChildDataElement.b) && this.c == boxChildDataElement.c;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.c) + (this.b.hashCode() * 31);
    }

    @Override // androidx.compose.ui.node.T
    public final androidx.compose.ui.p l() {
        C0402o c0402o = new C0402o();
        c0402o.n = this.b;
        c0402o.o = this.c;
        return c0402o;
    }

    @Override // androidx.compose.ui.node.T
    public final void n(androidx.compose.ui.p pVar) {
        C0402o c0402o = (C0402o) pVar;
        c0402o.n = this.b;
        c0402o.o = this.c;
    }
}

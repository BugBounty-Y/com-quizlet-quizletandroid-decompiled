package androidx.compose.ui.layout;

import kotlin.Metadata;

@Metadata
/* loaded from: classes.dex */
final class LayoutIdElement extends androidx.compose.ui.node.T {
    public final String b;

    public LayoutIdElement(String str) {
        this.b = str;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof LayoutIdElement) && this.b.equals(((LayoutIdElement) obj).b);
    }

    public final int hashCode() {
        return this.b.hashCode();
    }

    @Override // androidx.compose.ui.node.T
    public final androidx.compose.ui.p l() {
        C0898t c0898t = new C0898t();
        c0898t.n = this.b;
        return c0898t;
    }

    @Override // androidx.compose.ui.node.T
    public final void n(androidx.compose.ui.p pVar) {
        ((C0898t) pVar).n = this.b;
    }

    public final String toString() {
        return "LayoutIdElement(layoutId=" + ((Object) this.b) + ')';
    }
}

package androidx.compose.ui.layout;

import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes.dex */
final class LayoutElement extends androidx.compose.ui.node.T {
    public final kotlin.jvm.functions.c b;

    public LayoutElement(kotlin.jvm.functions.c cVar) {
        this.b = cVar;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof LayoutElement) && Intrinsics.b(this.b, ((LayoutElement) obj).b);
    }

    public final int hashCode() {
        return this.b.hashCode();
    }

    @Override // androidx.compose.ui.node.T
    public final androidx.compose.ui.p l() {
        C0902x c0902x = new C0902x();
        c0902x.n = this.b;
        return c0902x;
    }

    @Override // androidx.compose.ui.node.T
    public final void n(androidx.compose.ui.p pVar) {
        ((C0902x) pVar).n = this.b;
    }

    public final String toString() {
        return "LayoutElement(measure=" + this.b + ')';
    }
}

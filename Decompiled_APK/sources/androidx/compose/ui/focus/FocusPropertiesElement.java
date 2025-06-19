package androidx.compose.ui.focus;

import androidx.compose.ui.node.T;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes.dex */
final class FocusPropertiesElement extends T {
    public final m b;

    public FocusPropertiesElement(m mVar) {
        this.b = mVar;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof FocusPropertiesElement) && Intrinsics.b(this.b, ((FocusPropertiesElement) obj).b);
    }

    public final int hashCode() {
        return i.b.hashCode();
    }

    @Override // androidx.compose.ui.node.T
    public final androidx.compose.ui.p l() {
        o oVar = new o();
        oVar.n = this.b;
        return oVar;
    }

    @Override // androidx.compose.ui.node.T
    public final void n(androidx.compose.ui.p pVar) {
        ((o) pVar).n = this.b;
    }

    public final String toString() {
        return "FocusPropertiesElement(scope=" + this.b + ')';
    }
}

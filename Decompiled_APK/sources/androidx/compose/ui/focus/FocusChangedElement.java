package androidx.compose.ui.focus;

import androidx.compose.ui.node.T;
import kotlin.Metadata;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes.dex */
final class FocusChangedElement extends T {
    public final Function1 b;

    public FocusChangedElement(Function1 function1) {
        this.b = function1;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof FocusChangedElement) && Intrinsics.b(this.b, ((FocusChangedElement) obj).b);
    }

    public final int hashCode() {
        return this.b.hashCode();
    }

    @Override // androidx.compose.ui.node.T
    public final androidx.compose.ui.p l() {
        b bVar = new b();
        bVar.n = this.b;
        return bVar;
    }

    @Override // androidx.compose.ui.node.T
    public final void n(androidx.compose.ui.p pVar) {
        ((b) pVar).n = this.b;
    }

    public final String toString() {
        return "FocusChangedElement(onFocusChanged=" + this.b + ')';
    }
}

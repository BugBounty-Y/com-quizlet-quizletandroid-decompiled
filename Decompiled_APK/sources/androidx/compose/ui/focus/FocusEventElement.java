package androidx.compose.ui.focus;

import androidx.compose.ui.node.T;
import kotlin.Metadata;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes.dex */
final class FocusEventElement extends T {
    public final Function1 b;

    public FocusEventElement(Function1 function1) {
        this.b = function1;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof FocusEventElement) && Intrinsics.b(this.b, ((FocusEventElement) obj).b);
    }

    public final int hashCode() {
        return this.b.hashCode();
    }

    @Override // androidx.compose.ui.node.T
    public final androidx.compose.ui.p l() {
        e eVar = new e();
        eVar.n = this.b;
        return eVar;
    }

    @Override // androidx.compose.ui.node.T
    public final void n(androidx.compose.ui.p pVar) {
        ((e) pVar).n = this.b;
    }

    public final String toString() {
        return "FocusEventElement(onFocusEvent=" + this.b + ')';
    }
}

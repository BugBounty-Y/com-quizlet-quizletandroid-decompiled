package androidx.compose.foundation.text.handwriting;

import androidx.compose.ui.node.T;
import androidx.compose.ui.p;
import kotlin.Metadata;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes.dex */
final class StylusHandwritingElementWithNegativePadding extends T {
    public final Function0 b;

    public StylusHandwritingElementWithNegativePadding(Function0 function0) {
        this.b = function0;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof StylusHandwritingElementWithNegativePadding) && Intrinsics.b(this.b, ((StylusHandwritingElementWithNegativePadding) obj).b);
    }

    public final int hashCode() {
        return this.b.hashCode();
    }

    @Override // androidx.compose.ui.node.T
    public final p l() {
        return new d(this.b);
    }

    @Override // androidx.compose.ui.node.T
    public final void n(p pVar) {
        ((d) pVar).p = this.b;
    }

    public final String toString() {
        return "StylusHandwritingElementWithNegativePadding(onHandwritingSlopExceeded=" + this.b + ')';
    }
}

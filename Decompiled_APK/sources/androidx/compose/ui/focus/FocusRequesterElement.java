package androidx.compose.ui.focus;

import androidx.compose.ui.node.T;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes.dex */
final class FocusRequesterElement extends T {
    public final p b;

    public FocusRequesterElement(p pVar) {
        this.b = pVar;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof FocusRequesterElement) && Intrinsics.b(this.b, ((FocusRequesterElement) obj).b);
    }

    public final int hashCode() {
        return this.b.hashCode();
    }

    @Override // androidx.compose.ui.node.T
    public final androidx.compose.ui.p l() {
        r rVar = new r();
        rVar.n = this.b;
        return rVar;
    }

    @Override // androidx.compose.ui.node.T
    public final void n(androidx.compose.ui.p pVar) {
        r rVar = (r) pVar;
        rVar.n.a.n(rVar);
        p pVar2 = this.b;
        rVar.n = pVar2;
        pVar2.a.b(rVar);
    }

    public final String toString() {
        return "FocusRequesterElement(focusRequester=" + this.b + ')';
    }
}

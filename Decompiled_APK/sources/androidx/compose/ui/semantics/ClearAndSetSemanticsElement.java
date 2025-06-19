package androidx.compose.ui.semantics;

import androidx.compose.ui.node.T;
import kotlin.Metadata;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes.dex */
public final class ClearAndSetSemanticsElement extends T implements l {
    public final Function1 b;

    public ClearAndSetSemanticsElement(Function1 function1) {
        this.b = function1;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof ClearAndSetSemanticsElement) && Intrinsics.b(this.b, ((ClearAndSetSemanticsElement) obj).b);
    }

    public final int hashCode() {
        return this.b.hashCode();
    }

    @Override // androidx.compose.ui.node.T
    public final androidx.compose.ui.p l() {
        return new c(false, true, this.b);
    }

    @Override // androidx.compose.ui.semantics.l
    public final k m() {
        k kVar = new k();
        kVar.b = false;
        kVar.c = true;
        this.b.invoke(kVar);
        return kVar;
    }

    @Override // androidx.compose.ui.node.T
    public final void n(androidx.compose.ui.p pVar) {
        ((c) pVar).p = this.b;
    }

    public final String toString() {
        return "ClearAndSetSemanticsElement(properties=" + this.b + ')';
    }
}

package androidx.compose.ui.semantics;

import androidx.compose.ui.node.T;
import kotlin.Metadata;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes.dex */
public final class AppendedSemanticsElement extends T implements l {
    public final boolean b;
    public final Function1 c;

    public AppendedSemanticsElement(Function1 function1, boolean z) {
        this.b = z;
        this.c = function1;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof AppendedSemanticsElement)) {
            return false;
        }
        AppendedSemanticsElement appendedSemanticsElement = (AppendedSemanticsElement) obj;
        return this.b == appendedSemanticsElement.b && Intrinsics.b(this.c, appendedSemanticsElement.c);
    }

    public final int hashCode() {
        return this.c.hashCode() + (Boolean.hashCode(this.b) * 31);
    }

    @Override // androidx.compose.ui.node.T
    public final androidx.compose.ui.p l() {
        return new c(this.b, false, this.c);
    }

    @Override // androidx.compose.ui.semantics.l
    public final k m() {
        k kVar = new k();
        kVar.b = this.b;
        this.c.invoke(kVar);
        return kVar;
    }

    @Override // androidx.compose.ui.node.T
    public final void n(androidx.compose.ui.p pVar) {
        c cVar = (c) pVar;
        cVar.n = this.b;
        cVar.p = this.c;
    }

    public final String toString() {
        return "AppendedSemanticsElement(mergeDescendants=" + this.b + ", properties=" + this.c + ')';
    }
}

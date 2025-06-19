package androidx.compose.ui.draw;

import androidx.compose.ui.node.T;
import androidx.compose.ui.p;
import kotlin.Metadata;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes.dex */
final class DrawBehindElement extends T {
    public final Function1 b;

    public DrawBehindElement(Function1 function1) {
        this.b = function1;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof DrawBehindElement) && Intrinsics.b(this.b, ((DrawBehindElement) obj).b);
    }

    public final int hashCode() {
        return this.b.hashCode();
    }

    @Override // androidx.compose.ui.node.T
    public final p l() {
        e eVar = new e();
        eVar.n = this.b;
        return eVar;
    }

    @Override // androidx.compose.ui.node.T
    public final void n(p pVar) {
        ((e) pVar).n = this.b;
    }

    public final String toString() {
        return "DrawBehindElement(onDraw=" + this.b + ')';
    }
}

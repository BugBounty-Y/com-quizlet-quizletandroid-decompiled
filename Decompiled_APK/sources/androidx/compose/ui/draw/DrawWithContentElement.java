package androidx.compose.ui.draw;

import androidx.compose.ui.node.T;
import androidx.compose.ui.p;
import kotlin.Metadata;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes.dex */
final class DrawWithContentElement extends T {
    public final Function1 b;

    public DrawWithContentElement(Function1 function1) {
        this.b = function1;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof DrawWithContentElement) && Intrinsics.b(this.b, ((DrawWithContentElement) obj).b);
    }

    public final int hashCode() {
        return this.b.hashCode();
    }

    @Override // androidx.compose.ui.node.T
    public final p l() {
        h hVar = new h();
        hVar.n = this.b;
        return hVar;
    }

    @Override // androidx.compose.ui.node.T
    public final void n(p pVar) {
        ((h) pVar).n = this.b;
    }

    public final String toString() {
        return "DrawWithContentElement(onDraw=" + this.b + ')';
    }
}

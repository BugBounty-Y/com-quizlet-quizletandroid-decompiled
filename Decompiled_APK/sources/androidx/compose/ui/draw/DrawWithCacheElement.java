package androidx.compose.ui.draw;

import androidx.compose.ui.node.T;
import androidx.compose.ui.p;
import kotlin.Metadata;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes.dex */
final class DrawWithCacheElement extends T {
    public final Function1 b;

    public DrawWithCacheElement(Function1 function1) {
        this.b = function1;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof DrawWithCacheElement) && Intrinsics.b(this.b, ((DrawWithCacheElement) obj).b);
    }

    public final int hashCode() {
        return this.b.hashCode();
    }

    @Override // androidx.compose.ui.node.T
    public final p l() {
        return new c(new d(), this.b);
    }

    @Override // androidx.compose.ui.node.T
    public final void n(p pVar) {
        c cVar = (c) pVar;
        cVar.q = this.b;
        cVar.M0();
    }

    public final String toString() {
        return "DrawWithCacheElement(onBuildDrawCache=" + this.b + ')';
    }
}

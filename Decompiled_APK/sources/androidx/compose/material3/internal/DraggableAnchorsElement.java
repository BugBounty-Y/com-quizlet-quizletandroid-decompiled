package androidx.compose.material3.internal;

import androidx.compose.foundation.gestures.EnumC0320d0;
import kotlin.Metadata;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes.dex */
final class DraggableAnchorsElement<T> extends androidx.compose.ui.node.T {
    public final androidx.work.impl.model.t b;
    public final Function2 c;
    public final EnumC0320d0 d;

    public DraggableAnchorsElement(androidx.work.impl.model.t tVar, Function2 function2, EnumC0320d0 enumC0320d0) {
        this.b = tVar;
        this.c = function2;
        this.d = enumC0320d0;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof DraggableAnchorsElement)) {
            return false;
        }
        DraggableAnchorsElement draggableAnchorsElement = (DraggableAnchorsElement) obj;
        return Intrinsics.b(this.b, draggableAnchorsElement.b) && this.c == draggableAnchorsElement.c && this.d == draggableAnchorsElement.d;
    }

    public final int hashCode() {
        return this.d.hashCode() + ((this.c.hashCode() + (this.b.hashCode() * 31)) * 31);
    }

    @Override // androidx.compose.ui.node.T
    public final androidx.compose.ui.p l() {
        C0660y c0660y = new C0660y();
        c0660y.n = this.b;
        c0660y.o = this.c;
        c0660y.p = this.d;
        return c0660y;
    }

    @Override // androidx.compose.ui.node.T
    public final void n(androidx.compose.ui.p pVar) {
        C0660y c0660y = (C0660y) pVar;
        c0660y.n = this.b;
        c0660y.o = this.c;
        c0660y.p = this.d;
    }
}

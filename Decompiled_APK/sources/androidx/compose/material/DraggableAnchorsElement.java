package androidx.compose.material;

import androidx.compose.animation.C0281h;
import androidx.compose.foundation.gestures.EnumC0320d0;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes.dex */
final class DraggableAnchorsElement<T> extends androidx.compose.ui.node.T {
    public final C0575s b;
    public final C0281h c;

    public DraggableAnchorsElement(C0575s c0575s, C0281h c0281h) {
        this.b = c0575s;
        this.c = c0281h;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof DraggableAnchorsElement)) {
            return false;
        }
        DraggableAnchorsElement draggableAnchorsElement = (DraggableAnchorsElement) obj;
        return Intrinsics.b(this.b, draggableAnchorsElement.b) && this.c == draggableAnchorsElement.c;
    }

    public final int hashCode() {
        return EnumC0320d0.a.hashCode() + ((this.c.hashCode() + (this.b.hashCode() * 31)) * 31);
    }

    @Override // androidx.compose.ui.node.T
    public final androidx.compose.ui.p l() {
        C0582z c0582z = new C0582z();
        c0582z.n = this.b;
        c0582z.o = this.c;
        c0582z.p = EnumC0320d0.a;
        return c0582z;
    }

    @Override // androidx.compose.ui.node.T
    public final void n(androidx.compose.ui.p pVar) {
        C0582z c0582z = (C0582z) pVar;
        c0582z.n = this.b;
        c0582z.o = this.c;
        c0582z.p = EnumC0320d0.a;
    }
}

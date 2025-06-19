package androidx.compose.foundation.gestures;

import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes.dex */
public final class DraggableElement extends androidx.compose.ui.node.T {
    public final Z b;
    public final EnumC0320d0 c;
    public final boolean d;
    public final androidx.compose.foundation.interaction.l e;
    public final boolean f;
    public final S g;
    public final kotlin.jvm.functions.c h;
    public final boolean i;

    public DraggableElement(Z z, EnumC0320d0 enumC0320d0, boolean z2, androidx.compose.foundation.interaction.l lVar, boolean z3, S s, kotlin.jvm.functions.c cVar, boolean z4) {
        this.b = z;
        this.c = enumC0320d0;
        this.d = z2;
        this.e = lVar;
        this.f = z3;
        this.g = s;
        this.h = cVar;
        this.i = z4;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || DraggableElement.class != obj.getClass()) {
            return false;
        }
        DraggableElement draggableElement = (DraggableElement) obj;
        return Intrinsics.b(this.b, draggableElement.b) && this.c == draggableElement.c && this.d == draggableElement.d && Intrinsics.b(this.e, draggableElement.e) && this.f == draggableElement.f && Intrinsics.b(this.g, draggableElement.g) && Intrinsics.b(this.h, draggableElement.h) && this.i == draggableElement.i;
    }

    public final int hashCode() {
        int iG = androidx.compose.animation.d0.g((this.c.hashCode() + (this.b.hashCode() * 31)) * 31, 31, this.d);
        androidx.compose.foundation.interaction.l lVar = this.e;
        return Boolean.hashCode(this.i) + ((this.h.hashCode() + ((this.g.hashCode() + androidx.compose.animation.d0.g((iG + (lVar != null ? lVar.hashCode() : 0)) * 31, 31, this.f)) * 31)) * 31);
    }

    @Override // androidx.compose.ui.node.T
    public final androidx.compose.ui.p l() {
        C0321e c0321e = C0321e.d;
        EnumC0320d0 enumC0320d0 = this.c;
        Y y = new Y(c0321e, this.d, this.e, enumC0320d0);
        y.x = this.b;
        y.y = enumC0320d0;
        y.z = this.f;
        y.A = this.g;
        y.B = this.h;
        y.C = this.i;
        return y;
    }

    @Override // androidx.compose.ui.node.T
    public final void n(androidx.compose.ui.p pVar) {
        boolean z;
        boolean z2;
        Y y = (Y) pVar;
        C0321e c0321e = C0321e.d;
        Z z3 = y.x;
        Z z4 = this.b;
        if (Intrinsics.b(z3, z4)) {
            z = false;
        } else {
            y.x = z4;
            z = true;
        }
        EnumC0320d0 enumC0320d0 = y.y;
        EnumC0320d0 enumC0320d02 = this.c;
        if (enumC0320d0 != enumC0320d02) {
            y.y = enumC0320d02;
            z = true;
        }
        boolean z5 = y.C;
        boolean z6 = this.i;
        if (z5 != z6) {
            y.C = z6;
            z2 = true;
        } else {
            z2 = z;
        }
        y.A = this.g;
        y.B = this.h;
        y.z = this.f;
        y.X0(c0321e, this.d, this.e, enumC0320d02, z2);
    }
}

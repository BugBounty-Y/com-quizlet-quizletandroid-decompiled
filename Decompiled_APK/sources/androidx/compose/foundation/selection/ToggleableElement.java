package androidx.compose.foundation.selection;

import androidx.compose.animation.d0;
import androidx.compose.foundation.InterfaceC0461p0;
import androidx.compose.foundation.interaction.l;
import androidx.compose.ui.node.AbstractC0910f;
import androidx.compose.ui.node.T;
import androidx.compose.ui.p;
import androidx.compose.ui.semantics.h;
import kotlin.Metadata;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes.dex */
final class ToggleableElement extends T {
    public final boolean b;
    public final l c;
    public final InterfaceC0461p0 d;
    public final boolean e;
    public final h f;
    public final Function1 g;

    public ToggleableElement(boolean z, l lVar, InterfaceC0461p0 interfaceC0461p0, boolean z2, h hVar, Function1 function1) {
        this.b = z;
        this.c = lVar;
        this.d = interfaceC0461p0;
        this.e = z2;
        this.f = hVar;
        this.g = function1;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || ToggleableElement.class != obj.getClass()) {
            return false;
        }
        ToggleableElement toggleableElement = (ToggleableElement) obj;
        return this.b == toggleableElement.b && Intrinsics.b(this.c, toggleableElement.c) && Intrinsics.b(this.d, toggleableElement.d) && this.e == toggleableElement.e && Intrinsics.b(this.f, toggleableElement.f) && this.g == toggleableElement.g;
    }

    public final int hashCode() {
        int iHashCode = Boolean.hashCode(this.b) * 31;
        l lVar = this.c;
        int iHashCode2 = (iHashCode + (lVar != null ? lVar.hashCode() : 0)) * 31;
        InterfaceC0461p0 interfaceC0461p0 = this.d;
        int iG = d0.g((iHashCode2 + (interfaceC0461p0 != null ? interfaceC0461p0.hashCode() : 0)) * 31, 31, this.e);
        h hVar = this.f;
        return this.g.hashCode() + ((iG + (hVar != null ? Integer.hashCode(hVar.a) : 0)) * 31);
    }

    @Override // androidx.compose.ui.node.T
    public final p l() {
        return new f(this.b, this.c, this.d, this.e, this.f, this.g);
    }

    @Override // androidx.compose.ui.node.T
    public final void n(p pVar) {
        f fVar = (f) pVar;
        boolean z = fVar.H;
        boolean z2 = this.b;
        if (z != z2) {
            fVar.H = z2;
            AbstractC0910f.p(fVar);
        }
        fVar.I = this.g;
        fVar.T0(this.c, this.d, this.e, null, this.f, fVar.J);
    }
}

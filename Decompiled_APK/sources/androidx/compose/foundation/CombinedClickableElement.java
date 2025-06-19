package androidx.compose.foundation;

import androidx.compose.ui.node.AbstractC0910f;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes.dex */
final class CombinedClickableElement extends androidx.compose.ui.node.T {
    public final androidx.compose.foundation.interaction.l b;
    public final InterfaceC0461p0 c;
    public final boolean d;
    public final Function0 e;
    public final Function0 f;

    public CombinedClickableElement(androidx.compose.foundation.interaction.l lVar, InterfaceC0461p0 interfaceC0461p0, boolean z, Function0 function0, Function0 function02) {
        this.b = lVar;
        this.c = interfaceC0461p0;
        this.d = z;
        this.e = function0;
        this.f = function02;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || CombinedClickableElement.class != obj.getClass()) {
            return false;
        }
        CombinedClickableElement combinedClickableElement = (CombinedClickableElement) obj;
        return Intrinsics.b(this.b, combinedClickableElement.b) && Intrinsics.b(this.c, combinedClickableElement.c) && this.d == combinedClickableElement.d && this.e == combinedClickableElement.e && this.f == combinedClickableElement.f;
    }

    public final int hashCode() {
        androidx.compose.foundation.interaction.l lVar = this.b;
        int iHashCode = (lVar != null ? lVar.hashCode() : 0) * 31;
        InterfaceC0461p0 interfaceC0461p0 = this.c;
        int iHashCode2 = (this.e.hashCode() + androidx.compose.animation.d0.g((iHashCode + (interfaceC0461p0 != null ? interfaceC0461p0.hashCode() : 0)) * 31, 29791, this.d)) * 961;
        Function0 function0 = this.f;
        return (iHashCode2 + (function0 != null ? function0.hashCode() : 0)) * 31;
    }

    @Override // androidx.compose.ui.node.T
    public final androidx.compose.ui.p l() {
        J j = new J(this.b, this.c, this.d, null, null, this.e);
        j.H = this.f;
        return j;
    }

    @Override // androidx.compose.ui.node.T
    public final void n(androidx.compose.ui.p pVar) {
        androidx.compose.ui.input.pointer.B b;
        J j = (J) pVar;
        j.getClass();
        boolean z = false;
        boolean z2 = j.H == null;
        Function0 function0 = this.f;
        if (z2 != (function0 == null)) {
            j.R0();
            AbstractC0910f.p(j);
            z = true;
        }
        j.H = function0;
        boolean z3 = j.t;
        boolean z4 = this.d;
        boolean z5 = z3 != z4 ? true : z;
        j.T0(this.b, this.c, z4, null, null, this.e);
        if (!z5 || (b = j.x) == null) {
            return;
        }
        b.O0();
        Unit unit = Unit.a;
    }
}

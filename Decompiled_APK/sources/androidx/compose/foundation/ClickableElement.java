package androidx.compose.foundation;

import kotlin.Metadata;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes.dex */
final class ClickableElement extends androidx.compose.ui.node.T {
    public final androidx.compose.foundation.interaction.l b;
    public final InterfaceC0461p0 c;
    public final boolean d;
    public final String e;
    public final androidx.compose.ui.semantics.h f;
    public final Function0 g;

    public ClickableElement(androidx.compose.foundation.interaction.l lVar, InterfaceC0461p0 interfaceC0461p0, boolean z, String str, androidx.compose.ui.semantics.h hVar, Function0 function0) {
        this.b = lVar;
        this.c = interfaceC0461p0;
        this.d = z;
        this.e = str;
        this.f = hVar;
        this.g = function0;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || ClickableElement.class != obj.getClass()) {
            return false;
        }
        ClickableElement clickableElement = (ClickableElement) obj;
        return Intrinsics.b(this.b, clickableElement.b) && Intrinsics.b(this.c, clickableElement.c) && this.d == clickableElement.d && Intrinsics.b(this.e, clickableElement.e) && Intrinsics.b(this.f, clickableElement.f) && this.g == clickableElement.g;
    }

    public final int hashCode() {
        androidx.compose.foundation.interaction.l lVar = this.b;
        int iHashCode = (lVar != null ? lVar.hashCode() : 0) * 31;
        InterfaceC0461p0 interfaceC0461p0 = this.c;
        int iG = androidx.compose.animation.d0.g((iHashCode + (interfaceC0461p0 != null ? interfaceC0461p0.hashCode() : 0)) * 31, 31, this.d);
        String str = this.e;
        int iHashCode2 = (iG + (str != null ? str.hashCode() : 0)) * 31;
        androidx.compose.ui.semantics.h hVar = this.f;
        return this.g.hashCode() + ((iHashCode2 + (hVar != null ? Integer.hashCode(hVar.a) : 0)) * 31);
    }

    @Override // androidx.compose.ui.node.T
    public final androidx.compose.ui.p l() {
        return new E(this.b, this.c, this.d, this.e, this.f, this.g);
    }

    @Override // androidx.compose.ui.node.T
    public final void n(androidx.compose.ui.p pVar) {
        ((E) pVar).T0(this.b, this.c, this.d, this.e, this.f, this.g);
    }
}

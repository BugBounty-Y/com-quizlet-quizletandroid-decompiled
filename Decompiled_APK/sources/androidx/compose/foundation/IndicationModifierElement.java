package androidx.compose.foundation;

import androidx.compose.ui.node.InterfaceC0917m;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes.dex */
final class IndicationModifierElement extends androidx.compose.ui.node.T {
    public final androidx.compose.foundation.interaction.k b;
    public final InterfaceC0461p0 c;

    public IndicationModifierElement(androidx.compose.foundation.interaction.k kVar, InterfaceC0461p0 interfaceC0461p0) {
        this.b = kVar;
        this.c = interfaceC0461p0;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof IndicationModifierElement)) {
            return false;
        }
        IndicationModifierElement indicationModifierElement = (IndicationModifierElement) obj;
        return Intrinsics.b(this.b, indicationModifierElement.b) && Intrinsics.b(this.c, indicationModifierElement.c);
    }

    public final int hashCode() {
        return this.c.hashCode() + (this.b.hashCode() * 31);
    }

    @Override // androidx.compose.ui.node.T
    public final androidx.compose.ui.p l() {
        InterfaceC0917m interfaceC0917mB = this.c.b(this.b);
        C0459o0 c0459o0 = new C0459o0();
        c0459o0.p = interfaceC0917mB;
        c0459o0.M0(interfaceC0917mB);
        return c0459o0;
    }

    @Override // androidx.compose.ui.node.T
    public final void n(androidx.compose.ui.p pVar) {
        C0459o0 c0459o0 = (C0459o0) pVar;
        InterfaceC0917m interfaceC0917mB = this.c.b(this.b);
        c0459o0.N0(c0459o0.p);
        c0459o0.p = interfaceC0917mB;
        c0459o0.M0(interfaceC0917mB);
    }
}

package androidx.compose.ui.input.pointer;

import androidx.compose.ui.node.T;
import kotlin.Metadata;

@Metadata
/* loaded from: classes.dex */
public final class PointerHoverIconModifierElement extends T {
    public final C0878a b;

    public PointerHoverIconModifierElement(C0878a c0878a) {
        this.b = c0878a;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof PointerHoverIconModifierElement) {
            return this.b.equals(((PointerHoverIconModifierElement) obj).b);
        }
        return false;
    }

    public final int hashCode() {
        return Boolean.hashCode(false) + (this.b.b * 31);
    }

    @Override // androidx.compose.ui.node.T
    public final androidx.compose.ui.p l() {
        C0878a c0878a = this.b;
        h hVar = new h();
        hVar.n = c0878a;
        return hVar;
    }

    @Override // androidx.compose.ui.node.T
    public final void n(androidx.compose.ui.p pVar) {
        h hVar = (h) pVar;
        C0878a c0878a = hVar.n;
        C0878a c0878a2 = this.b;
        if (c0878a.equals(c0878a2)) {
            return;
        }
        hVar.n = c0878a2;
        if (hVar.o) {
            hVar.N0();
        }
    }

    public final String toString() {
        return "PointerHoverIconModifierElement(icon=" + this.b + ", overrideDescendants=false)";
    }
}

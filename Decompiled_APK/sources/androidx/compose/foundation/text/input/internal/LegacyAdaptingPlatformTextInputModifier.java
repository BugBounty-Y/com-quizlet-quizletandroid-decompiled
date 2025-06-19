package androidx.compose.foundation.text.input.internal;

import androidx.compose.foundation.text.C0492h0;
import androidx.compose.foundation.text.selection.i0;
import androidx.compose.ui.node.T;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes.dex */
final class LegacyAdaptingPlatformTextInputModifier extends T {
    public final g b;
    public final C0492h0 c;
    public final i0 d;

    public LegacyAdaptingPlatformTextInputModifier(g gVar, C0492h0 c0492h0, i0 i0Var) {
        this.b = gVar;
        this.c = c0492h0;
        this.d = i0Var;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof LegacyAdaptingPlatformTextInputModifier)) {
            return false;
        }
        LegacyAdaptingPlatformTextInputModifier legacyAdaptingPlatformTextInputModifier = (LegacyAdaptingPlatformTextInputModifier) obj;
        return Intrinsics.b(this.b, legacyAdaptingPlatformTextInputModifier.b) && Intrinsics.b(this.c, legacyAdaptingPlatformTextInputModifier.c) && Intrinsics.b(this.d, legacyAdaptingPlatformTextInputModifier.d);
    }

    public final int hashCode() {
        return this.d.hashCode() + ((this.c.hashCode() + (this.b.hashCode() * 31)) * 31);
    }

    @Override // androidx.compose.ui.node.T
    public final androidx.compose.ui.p l() {
        i0 i0Var = this.d;
        return new w(this.b, this.c, i0Var);
    }

    @Override // androidx.compose.ui.node.T
    public final void n(androidx.compose.ui.p pVar) throws Throwable {
        w wVar = (w) pVar;
        if (wVar.m) {
            wVar.n.d();
            wVar.n.k(wVar);
        }
        g gVar = this.b;
        wVar.n = gVar;
        if (wVar.m) {
            if (gVar.a != null) {
                throw new IllegalStateException("Expected textInputModifierNode to be null");
            }
            gVar.a = wVar;
        }
        wVar.o = this.c;
        wVar.p = this.d;
    }

    public final String toString() {
        return "LegacyAdaptingPlatformTextInputModifier(serviceAdapter=" + this.b + ", legacyTextFieldState=" + this.c + ", textFieldSelectionManager=" + this.d + ')';
    }
}

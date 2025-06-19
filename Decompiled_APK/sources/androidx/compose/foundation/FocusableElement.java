package androidx.compose.foundation;

import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes.dex */
final class FocusableElement extends androidx.compose.ui.node.T {
    public final androidx.compose.foundation.interaction.l b;

    public FocusableElement(androidx.compose.foundation.interaction.l lVar) {
        this.b = lVar;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof FocusableElement) {
            return Intrinsics.b(this.b, ((FocusableElement) obj).b);
        }
        return false;
    }

    public final int hashCode() {
        androidx.compose.foundation.interaction.l lVar = this.b;
        if (lVar != null) {
            return lVar.hashCode();
        }
        return 0;
    }

    @Override // androidx.compose.ui.node.T
    public final androidx.compose.ui.p l() {
        return new W(this.b);
    }

    @Override // androidx.compose.ui.node.T
    public final void n(androidx.compose.ui.p pVar) {
        ((W) pVar).P0(this.b);
    }
}

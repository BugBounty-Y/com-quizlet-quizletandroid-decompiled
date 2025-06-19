package androidx.compose.foundation.layout;

import androidx.compose.ui.layout.C0893n;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes.dex */
public final class WithAlignmentLineElement extends androidx.compose.ui.node.T {
    public final C0893n b;

    public WithAlignmentLineElement(C0893n c0893n) {
        this.b = c0893n;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        WithAlignmentLineElement withAlignmentLineElement = obj instanceof WithAlignmentLineElement ? (WithAlignmentLineElement) obj : null;
        if (withAlignmentLineElement == null) {
            return false;
        }
        return Intrinsics.b(this.b, withAlignmentLineElement.b);
    }

    public final int hashCode() {
        return this.b.hashCode();
    }

    @Override // androidx.compose.ui.node.T
    public final androidx.compose.ui.p l() {
        J0 j0 = new J0();
        j0.n = this.b;
        return j0;
    }

    @Override // androidx.compose.ui.node.T
    public final void n(androidx.compose.ui.p pVar) {
        ((J0) pVar).n = this.b;
    }
}

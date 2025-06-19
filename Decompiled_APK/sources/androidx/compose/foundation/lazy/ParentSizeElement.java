package androidx.compose.foundation.lazy;

import androidx.compose.runtime.H0;
import androidx.compose.ui.node.T;
import kotlin.Metadata;

@Metadata
/* loaded from: classes.dex */
final class ParentSizeElement extends T {
    public final H0 b;

    public ParentSizeElement(H0 h0) {
        this.b = h0;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof ParentSizeElement)) {
            return false;
        }
        ParentSizeElement parentSizeElement = (ParentSizeElement) obj;
        parentSizeElement.getClass();
        return this.b.equals(parentSizeElement.b);
    }

    public final int hashCode() {
        return Float.hashCode(1.0f) + (this.b.hashCode() * 961);
    }

    @Override // androidx.compose.ui.node.T
    public final androidx.compose.ui.p l() {
        E e = new E();
        e.n = 1.0f;
        e.o = this.b;
        return e;
    }

    @Override // androidx.compose.ui.node.T
    public final void n(androidx.compose.ui.p pVar) {
        E e = (E) pVar;
        e.n = 1.0f;
        e.o = this.b;
    }
}

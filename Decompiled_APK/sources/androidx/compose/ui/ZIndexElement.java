package androidx.compose.ui;

import androidx.compose.ui.node.T;
import kotlin.Metadata;

@Metadata
/* loaded from: classes.dex */
public final class ZIndexElement extends T {
    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof ZIndexElement)) {
            return false;
        }
        ((ZIndexElement) obj).getClass();
        return Float.compare(1.0f, 1.0f) == 0;
    }

    public final int hashCode() {
        return Float.hashCode(1.0f);
    }

    @Override // androidx.compose.ui.node.T
    public final p l() {
        u uVar = new u();
        uVar.n = 1.0f;
        return uVar;
    }

    @Override // androidx.compose.ui.node.T
    public final void n(p pVar) {
        ((u) pVar).n = 1.0f;
    }

    public final String toString() {
        return "ZIndexElement(zIndex=1.0)";
    }
}

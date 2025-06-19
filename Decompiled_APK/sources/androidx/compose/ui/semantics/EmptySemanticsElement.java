package androidx.compose.ui.semantics;

import androidx.compose.ui.node.T;
import kotlin.Metadata;

@Metadata
/* loaded from: classes.dex */
public final class EmptySemanticsElement extends T {
    public final e b;

    public EmptySemanticsElement(e eVar) {
        this.b = eVar;
    }

    public final boolean equals(Object obj) {
        return obj == this;
    }

    public final int hashCode() {
        return System.identityHashCode(this);
    }

    @Override // androidx.compose.ui.node.T
    public final androidx.compose.ui.p l() {
        return this.b;
    }

    @Override // androidx.compose.ui.node.T
    public final /* bridge */ /* synthetic */ void n(androidx.compose.ui.p pVar) {
    }
}

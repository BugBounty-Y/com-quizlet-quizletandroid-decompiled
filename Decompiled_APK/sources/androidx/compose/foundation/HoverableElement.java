package androidx.compose.foundation;

import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes.dex */
final class HoverableElement extends androidx.compose.ui.node.T {
    public final androidx.compose.foundation.interaction.l b;

    public HoverableElement(androidx.compose.foundation.interaction.l lVar) {
        this.b = lVar;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof HoverableElement) && Intrinsics.b(((HoverableElement) obj).b, this.b);
    }

    public final int hashCode() {
        return this.b.hashCode() * 31;
    }

    @Override // androidx.compose.ui.node.T
    public final androidx.compose.ui.p l() {
        C0310f0 c0310f0 = new C0310f0();
        c0310f0.n = this.b;
        return c0310f0;
    }

    @Override // androidx.compose.ui.node.T
    public final void n(androidx.compose.ui.p pVar) {
        C0310f0 c0310f0 = (C0310f0) pVar;
        androidx.compose.foundation.interaction.l lVar = c0310f0.n;
        androidx.compose.foundation.interaction.l lVar2 = this.b;
        if (Intrinsics.b(lVar, lVar2)) {
            return;
        }
        c0310f0.O0();
        c0310f0.n = lVar2;
    }
}

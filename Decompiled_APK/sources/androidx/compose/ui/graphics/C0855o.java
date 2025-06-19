package androidx.compose.ui.graphics;

import androidx.compose.foundation.text.selection.n0;
import androidx.compose.ui.node.InterfaceC0926w;
import kotlin.jvm.functions.Function1;

/* renamed from: androidx.compose.ui.graphics.o, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0855o extends androidx.compose.ui.p implements InterfaceC0926w {
    public Function1 n;

    public C0855o(Function1 function1) {
        this.n = function1;
    }

    @Override // androidx.compose.ui.p
    public final boolean B0() {
        return false;
    }

    @Override // androidx.compose.ui.node.InterfaceC0926w
    public final androidx.compose.ui.layout.L h(androidx.compose.ui.layout.M m, androidx.compose.ui.layout.J j, long j2) {
        androidx.compose.ui.layout.W wB = j.B(j2);
        return m.n0(wB.a, wB.b, kotlin.collections.V.c(), new n0(16, wB, this));
    }

    public final String toString() {
        return "BlockGraphicsLayerModifier(block=" + this.n + ')';
    }
}

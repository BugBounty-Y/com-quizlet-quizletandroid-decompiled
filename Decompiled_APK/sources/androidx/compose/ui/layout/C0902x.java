package androidx.compose.ui.layout;

import androidx.compose.ui.node.InterfaceC0926w;

/* renamed from: androidx.compose.ui.layout.x, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0902x extends androidx.compose.ui.p implements InterfaceC0926w {
    public kotlin.jvm.functions.c n;

    @Override // androidx.compose.ui.node.InterfaceC0926w
    public final L h(M m, J j, long j2) {
        return (L) this.n.invoke(m, j, new androidx.compose.ui.unit.a(j2));
    }

    public final String toString() {
        return "LayoutModifierImpl(measureBlock=" + this.n + ')';
    }
}

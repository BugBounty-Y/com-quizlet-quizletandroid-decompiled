package androidx.compose.foundation;

/* loaded from: classes.dex */
public abstract class U {
    static {
        new androidx.compose.ui.node.T() { // from class: androidx.compose.foundation.FocusableKt$FocusableInNonTouchModeElement$1
            public final boolean equals(Object obj) {
                return this == obj;
            }

            public final int hashCode() {
                return System.identityHashCode(this);
            }

            @Override // androidx.compose.ui.node.T
            public final androidx.compose.ui.p l() {
                return new Q();
            }

            @Override // androidx.compose.ui.node.T
            public final /* bridge */ /* synthetic */ void n(androidx.compose.ui.p pVar) {
            }
        };
    }

    public static final androidx.compose.ui.q a(androidx.compose.ui.q qVar, boolean z, androidx.compose.foundation.interaction.l lVar) {
        return qVar.g(z ? new FocusableElement(lVar) : androidx.compose.ui.n.b);
    }

    public static /* synthetic */ androidx.compose.ui.q b(androidx.compose.ui.q qVar, boolean z, int i) {
        if ((i & 1) != 0) {
            z = true;
        }
        return a(qVar, z, null);
    }
}

package androidx.compose.ui.layout;

import androidx.compose.ui.platform.C0971v;

/* loaded from: classes.dex */
public final class H extends V {
    public final /* synthetic */ int b;
    public final Object c;

    public /* synthetic */ H(Object obj, int i) {
        this.b = i;
        this.c = obj;
    }

    @Override // androidx.compose.ui.layout.V
    public final androidx.compose.ui.unit.k b() {
        switch (this.b) {
            case 0:
                return ((androidx.compose.ui.node.O) this.c).getLayoutDirection();
            default:
                return ((C0971v) this.c).getLayoutDirection();
        }
    }

    @Override // androidx.compose.ui.layout.V
    public final int c() {
        switch (this.b) {
            case 0:
                return ((androidx.compose.ui.node.O) this.c).k0();
            default:
                return ((C0971v) this.c).getRoot().x.r.a;
        }
    }
}

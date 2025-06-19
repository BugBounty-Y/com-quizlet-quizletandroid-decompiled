package androidx.compose.ui.node;

import androidx.compose.runtime.AbstractC0772a;
import androidx.compose.ui.platform.C0971v;

/* loaded from: classes.dex */
public final class s0 extends AbstractC0772a {
    @Override // androidx.compose.runtime.InterfaceC0790d
    public final void c(int i, Object obj) {
        ((E) this.b).y(i, (E) obj);
    }

    @Override // androidx.compose.runtime.InterfaceC0790d
    public final void e(int i, int i2, int i3) {
        ((E) this.b).I(i, i2, i3);
    }

    @Override // androidx.compose.runtime.InterfaceC0790d
    public final void f(int i, int i2) {
        ((E) this.b).O(i, i2);
    }

    @Override // androidx.compose.runtime.InterfaceC0790d
    public final /* bridge */ /* synthetic */ void i(int i, Object obj) {
    }

    @Override // androidx.compose.runtime.InterfaceC0790d
    public final void k() {
        C0971v c0971v = ((E) this.a).i;
        if (c0971v != null) {
            c0971v.t();
        }
    }

    @Override // androidx.compose.runtime.AbstractC0772a
    public final void m() {
        ((E) this.a).N();
    }
}

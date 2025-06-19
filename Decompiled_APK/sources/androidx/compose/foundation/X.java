package androidx.compose.foundation;

import androidx.compose.animation.core.C0242g;
import androidx.compose.ui.node.AbstractC0910f;
import androidx.compose.ui.node.InterfaceC0916l;

/* loaded from: classes.dex */
public final class X extends androidx.compose.ui.p implements InterfaceC0916l, androidx.compose.ui.node.c0 {
    public androidx.compose.foundation.lazy.layout.Y n;
    public boolean o;

    @Override // androidx.compose.ui.p
    public final boolean B0() {
        return false;
    }

    @Override // androidx.compose.ui.p
    public final void G0() {
        androidx.compose.foundation.lazy.layout.Y y = this.n;
        if (y != null) {
            y.c();
        }
        this.n = null;
    }

    @Override // androidx.compose.ui.node.c0
    public final void k0() {
        kotlin.jvm.internal.J j = new kotlin.jvm.internal.J();
        AbstractC0910f.s(this, new C0242g(1, j, this));
        androidx.compose.foundation.lazy.layout.Y y = (androidx.compose.foundation.lazy.layout.Y) j.a;
        if (this.o) {
            androidx.compose.foundation.lazy.layout.Y y2 = this.n;
            if (y2 != null) {
                y2.c();
            }
            if (y != null) {
                y.b();
            } else {
                y = null;
            }
            this.n = y;
        }
    }
}

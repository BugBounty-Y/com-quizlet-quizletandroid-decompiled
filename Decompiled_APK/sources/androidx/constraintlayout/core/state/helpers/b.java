package androidx.constraintlayout.core.state.helpers;

import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.constraintlayout.core.widgets.j;

/* loaded from: classes.dex */
public final class b extends androidx.constraintlayout.core.state.g {
    public int n0;
    public int o0;
    public androidx.constraintlayout.core.widgets.a p0;

    @Override // androidx.constraintlayout.core.state.g, androidx.constraintlayout.core.state.b, androidx.constraintlayout.core.state.h
    public final void apply() {
        s();
        int iK = AbstractC0147y.k(this.n0);
        int i = 1;
        if (iK != 1 && iK != 3) {
            i = iK != 4 ? iK != 5 ? 0 : 3 : 2;
        }
        androidx.constraintlayout.core.widgets.a aVar = this.p0;
        aVar.v0 = i;
        aVar.x0 = this.o0;
    }

    @Override // androidx.constraintlayout.core.state.b
    public final androidx.constraintlayout.core.state.b k(int i) {
        this.o0 = i;
        return this;
    }

    @Override // androidx.constraintlayout.core.state.b
    public final androidx.constraintlayout.core.state.b l(Float f) {
        this.o0 = this.k0.c(f);
        return this;
    }

    @Override // androidx.constraintlayout.core.state.g
    public final j s() {
        if (this.p0 == null) {
            this.p0 = new androidx.constraintlayout.core.widgets.a();
        }
        return this.p0;
    }
}

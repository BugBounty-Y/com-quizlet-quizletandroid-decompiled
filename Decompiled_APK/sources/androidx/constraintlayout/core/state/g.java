package androidx.constraintlayout.core.state;

import java.util.ArrayList;
import java.util.Collections;

/* loaded from: classes.dex */
public class g extends b implements androidx.constraintlayout.core.state.helpers.d {
    public final androidx.constraintlayout.compose.k k0;
    public final int l0;
    public final ArrayList m0;

    public g(androidx.constraintlayout.compose.k kVar, int i) {
        super(kVar);
        this.m0 = new ArrayList();
        this.k0 = kVar;
        this.l0 = i;
    }

    @Override // androidx.constraintlayout.core.state.b, androidx.constraintlayout.core.state.h
    public void apply() {
    }

    @Override // androidx.constraintlayout.core.state.b, androidx.constraintlayout.core.state.h
    public final androidx.constraintlayout.core.widgets.e b() {
        return s();
    }

    public final void q(Object... objArr) {
        Collections.addAll(this.m0, objArr);
    }

    public final void r() {
        super.apply();
    }

    public androidx.constraintlayout.core.widgets.j s() {
        return null;
    }
}

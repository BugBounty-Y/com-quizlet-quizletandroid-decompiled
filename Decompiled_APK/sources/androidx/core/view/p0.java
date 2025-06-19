package androidx.core.view;

import android.view.WindowInsets;

/* loaded from: classes.dex */
public class p0 extends s0 {
    public final WindowInsets.Builder c;

    public p0() {
        this.c = androidx.compose.ui.platform.H0.d();
    }

    @Override // androidx.core.view.s0
    public D0 b() {
        a();
        D0 d0H = D0.h(null, this.c.build());
        d0H.a.r(this.b);
        return d0H;
    }

    @Override // androidx.core.view.s0
    public void d(androidx.core.graphics.e eVar) {
        this.c.setMandatorySystemGestureInsets(eVar.d());
    }

    @Override // androidx.core.view.s0
    public void e(androidx.core.graphics.e eVar) {
        this.c.setStableInsets(eVar.d());
    }

    @Override // androidx.core.view.s0
    public void f(androidx.core.graphics.e eVar) {
        this.c.setSystemGestureInsets(eVar.d());
    }

    @Override // androidx.core.view.s0
    public void g(androidx.core.graphics.e eVar) {
        this.c.setSystemWindowInsets(eVar.d());
    }

    @Override // androidx.core.view.s0
    public void h(androidx.core.graphics.e eVar) {
        this.c.setTappableElementInsets(eVar.d());
    }

    public p0(D0 d0) {
        WindowInsets.Builder builderD;
        super(d0);
        WindowInsets windowInsetsG = d0.g();
        if (windowInsetsG != null) {
            builderD = o0.h(windowInsetsG);
        } else {
            builderD = androidx.compose.ui.platform.H0.d();
        }
        this.c = builderD;
    }
}

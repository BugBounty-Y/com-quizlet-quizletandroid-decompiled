package com.google.android.material.appbar;

import android.view.View;
import androidx.coordinatorlayout.widget.CoordinatorLayout;

/* loaded from: classes2.dex */
public abstract class m extends androidx.coordinatorlayout.widget.b {
    public n a;
    public int b = 0;

    public m() {
    }

    @Override // androidx.coordinatorlayout.widget.b
    public boolean l(CoordinatorLayout coordinatorLayout, View view, int i) {
        x(coordinatorLayout, view, i);
        if (this.a == null) {
            this.a = new n(view);
        }
        n nVar = this.a;
        View view2 = nVar.a;
        nVar.b = view2.getTop();
        nVar.c = view2.getLeft();
        this.a.a();
        int i2 = this.b;
        if (i2 == 0) {
            return true;
        }
        this.a.b(i2);
        this.b = 0;
        return true;
    }

    public final int w() {
        n nVar = this.a;
        if (nVar != null) {
            return nVar.d;
        }
        return 0;
    }

    public void x(CoordinatorLayout coordinatorLayout, View view, int i) {
        coordinatorLayout.r(i, view);
    }

    public m(int i) {
    }
}

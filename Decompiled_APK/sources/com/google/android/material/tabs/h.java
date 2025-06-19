package com.google.android.material.tabs;

import java.lang.ref.WeakReference;

/* loaded from: classes2.dex */
public final class h implements androidx.viewpager.widget.f {
    public final WeakReference a;
    public int b;
    public int c;

    public h(l lVar) {
        this.a = new WeakReference(lVar);
    }

    public final void a(float f, int i) {
        boolean z;
        l lVar = (l) this.a.get();
        if (lVar != null) {
            int i2 = this.c;
            boolean z2 = true;
            if (i2 != 2 || this.b == 1) {
                z = true;
            } else {
                z = true;
                z2 = false;
            }
            if (i2 == 2 && this.b == 0) {
                z = false;
            }
            lVar.o(i, f, z2, z, false);
        }
    }

    public final void b(int i) {
        l lVar = (l) this.a.get();
        if (lVar == null || lVar.getSelectedTabPosition() == i || i >= lVar.getTabCount()) {
            return;
        }
        int i2 = this.c;
        lVar.m(lVar.i(i), i2 == 0 || (i2 == 2 && this.b == 0));
    }
}

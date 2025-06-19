package com.google.android.material.bottomsheet;

import android.view.View;
import androidx.core.view.AbstractC1047f0;
import androidx.core.view.D0;
import androidx.core.view.m0;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.Iterator;
import java.util.List;

/* loaded from: classes2.dex */
public final class j extends AbstractC1047f0 {
    public final View c;
    public int d;
    public int e;
    public final int[] f;

    public j(View view) {
        super(0);
        this.f = new int[2];
        this.c = view;
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final void d(m0 m0Var) {
        this.c.setTranslationY(DefinitionKt.NO_Float_VALUE);
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final void e() {
        View view = this.c;
        int[] iArr = this.f;
        view.getLocationOnScreen(iArr);
        this.d = iArr[1];
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final D0 f(D0 d0, List list) {
        Iterator it2 = list.iterator();
        while (true) {
            if (!it2.hasNext()) {
                break;
            }
            if ((((m0) it2.next()).a.c() & 8) != 0) {
                this.c.setTranslationY(com.google.android.material.animation.a.c(this.e, r0.a.b(), 0));
                break;
            }
        }
        return d0;
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final androidx.work.impl.model.e g(androidx.work.impl.model.e eVar) {
        View view = this.c;
        int[] iArr = this.f;
        view.getLocationOnScreen(iArr);
        int i = this.d - iArr[1];
        this.e = i;
        view.setTranslationY(i);
        return eVar;
    }
}

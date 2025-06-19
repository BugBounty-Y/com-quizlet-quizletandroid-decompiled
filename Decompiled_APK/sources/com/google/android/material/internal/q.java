package com.google.android.material.internal;

import android.view.View;
import android.view.ViewGroup;
import androidx.appcompat.app.L;
import androidx.core.view.D0;
import androidx.core.view.V;
import com.quizlet.features.infra.legacyadapter.RecyclerViewFragment;
import java.lang.ref.WeakReference;
import java.util.WeakHashMap;

/* loaded from: classes2.dex */
public final class q implements s {
    public boolean a;
    public boolean b;
    public boolean c;
    public Object d;

    public void a() {
        com.quizlet.features.infra.legacyadapter.g gVar = (com.quizlet.features.infra.legacyadapter.g) ((WeakReference) this.d).get();
        if (gVar != null) {
            boolean z = this.b;
            RecyclerViewFragment recyclerViewFragment = gVar.a;
            recyclerViewFragment.e.setVisibility(z ? 0 : 8);
            int iOrdinal = ((this.b || this.a) ? com.quizlet.features.infra.legacyadapter.statemanager.a.a : this.c ? com.quizlet.features.infra.legacyadapter.statemanager.a.c : com.quizlet.features.infra.legacyadapter.statemanager.a.b).ordinal();
            if (iOrdinal == 0) {
                recyclerViewFragment.h.setVisibility(8);
            } else if (iOrdinal == 1) {
                recyclerViewFragment.h.setVisibility(0);
                if (recyclerViewFragment.p == null) {
                    recyclerViewFragment.p = recyclerViewFragment.R(recyclerViewFragment.h);
                }
                View view = recyclerViewFragment.p;
                if (recyclerViewFragment.isAdded()) {
                    ViewGroup viewGroup = (ViewGroup) view.getParent();
                    if (viewGroup != null) {
                        viewGroup.removeView(view);
                    }
                    recyclerViewFragment.h.removeAllViews();
                    recyclerViewFragment.h.addView(view);
                }
            } else if (iOrdinal == 2) {
                recyclerViewFragment.h.setVisibility(0);
                if (recyclerViewFragment.q == null) {
                    recyclerViewFragment.q = recyclerViewFragment.S(recyclerViewFragment.h);
                }
                View view2 = recyclerViewFragment.q;
                if (recyclerViewFragment.isAdded()) {
                    ViewGroup viewGroup2 = (ViewGroup) view2.getParent();
                    if (viewGroup2 != null) {
                        viewGroup2.removeView(view2);
                    }
                    recyclerViewFragment.h.removeAllViews();
                    recyclerViewFragment.h.addView(view2);
                }
            }
            boolean z2 = !this.b && this.a;
            recyclerViewFragment.U(z2);
            if (z2) {
                return;
            }
            recyclerViewFragment.j.setRefreshing(false);
        }
    }

    public void b(boolean z) {
        this.b = z;
        a();
    }

    public void c(boolean z) {
        this.a = z;
        a();
    }

    @Override // com.google.android.material.internal.s
    public D0 k(View view, D0 d0, com.google.android.gms.ads.internal.overlay.k kVar) {
        if (this.a) {
            kVar.d = d0.a() + kVar.d;
        }
        boolean zK = p.k(view);
        if (this.b) {
            if (zK) {
                kVar.c = d0.b() + kVar.c;
            } else {
                kVar.a = d0.b() + kVar.a;
            }
        }
        if (this.c) {
            if (zK) {
                kVar.a = d0.c() + kVar.a;
            } else {
                kVar.c = d0.c() + kVar.c;
            }
        }
        int i = kVar.a;
        int i2 = kVar.c;
        int i3 = kVar.d;
        WeakHashMap weakHashMap = V.a;
        view.setPaddingRelative(i, kVar.b, i2, i3);
        ((L) this.d).k(view, d0, kVar);
        return d0;
    }
}

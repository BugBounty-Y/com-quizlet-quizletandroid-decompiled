package com.quizlet.explanations.databinding;

import android.view.View;
import androidx.coordinatorlayout.widget.CoordinatorLayout;
import androidx.recyclerview.widget.RecyclerView;

/* loaded from: classes2.dex */
public final class k implements androidx.viewbinding.a {
    public final CoordinatorLayout a;
    public final RecyclerView b;
    public final n c;

    public k(CoordinatorLayout coordinatorLayout, RecyclerView recyclerView, n nVar) {
        this.a = coordinatorLayout;
        this.b = recyclerView;
        this.c = nVar;
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        return this.a;
    }
}

package com.quizlet.explanations.databinding;

import android.view.View;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.recyclerview.widget.RecyclerView;

/* loaded from: classes2.dex */
public final class h implements androidx.viewbinding.a {
    public final ConstraintLayout a;
    public final RecyclerView b;
    public final RecyclerView c;

    public h(ConstraintLayout constraintLayout, RecyclerView recyclerView, RecyclerView recyclerView2) {
        this.a = constraintLayout;
        this.b = recyclerView;
        this.c = recyclerView2;
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        return this.a;
    }
}

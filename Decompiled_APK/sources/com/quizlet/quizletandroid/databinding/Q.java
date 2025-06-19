package com.quizlet.quizletandroid.databinding;

import android.view.View;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.recyclerview.widget.RecyclerView;

/* loaded from: classes3.dex */
public final class Q implements androidx.viewbinding.a {
    public final ConstraintLayout a;
    public final RecyclerView b;

    public Q(ConstraintLayout constraintLayout, RecyclerView recyclerView) {
        this.a = constraintLayout;
        this.b = recyclerView;
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        return this.a;
    }
}

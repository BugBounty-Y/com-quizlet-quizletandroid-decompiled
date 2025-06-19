package com.quizlet.explanations.databinding;

import android.view.View;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.recyclerview.widget.RecyclerView;

/* loaded from: classes2.dex */
public final class d implements androidx.viewbinding.a {
    public final ConstraintLayout a;
    public final RecyclerView b;

    public d(ConstraintLayout constraintLayout, RecyclerView recyclerView) {
        this.a = constraintLayout;
        this.b = recyclerView;
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        return this.a;
    }
}

package com.quizlet.quizletandroid.databinding;

import android.view.View;
import android.widget.ProgressBar;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.recyclerview.widget.RecyclerView;

/* renamed from: com.quizlet.quizletandroid.databinding.o, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4611o implements androidx.viewbinding.a {
    public final ConstraintLayout a;
    public final ProgressBar b;
    public final RecyclerView c;

    public C4611o(ConstraintLayout constraintLayout, ProgressBar progressBar, RecyclerView recyclerView) {
        this.a = constraintLayout;
        this.b = progressBar;
        this.c = recyclerView;
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        return this.a;
    }
}

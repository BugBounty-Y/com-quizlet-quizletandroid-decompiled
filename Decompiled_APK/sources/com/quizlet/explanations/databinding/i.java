package com.quizlet.explanations.databinding;

import android.view.View;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.recyclerview.widget.RecyclerView;
import com.quizlet.partskit.widgets.QProgressBar;
import com.quizlet.partskit.widgets.QTextView;

/* loaded from: classes2.dex */
public final class i implements androidx.viewbinding.a {
    public final ConstraintLayout a;
    public final QTextView b;
    public final QProgressBar c;
    public final RecyclerView d;

    public i(ConstraintLayout constraintLayout, QTextView qTextView, QProgressBar qProgressBar, RecyclerView recyclerView) {
        this.a = constraintLayout;
        this.b = qTextView;
        this.c = qProgressBar;
        this.d = recyclerView;
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        return this.a;
    }
}

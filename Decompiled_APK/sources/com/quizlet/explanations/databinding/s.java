package com.quizlet.explanations.databinding;

import android.view.View;
import android.widget.ImageView;
import androidx.constraintlayout.widget.ConstraintLayout;
import com.quizlet.partskit.widgets.QTextView;

/* loaded from: classes2.dex */
public final class s implements androidx.viewbinding.a {
    public final ConstraintLayout a;
    public final ConstraintLayout b;
    public final ImageView c;
    public final QTextView d;

    public s(ConstraintLayout constraintLayout, ConstraintLayout constraintLayout2, ImageView imageView, QTextView qTextView) {
        this.a = constraintLayout;
        this.b = constraintLayout2;
        this.c = imageView;
        this.d = qTextView;
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        return this.a;
    }
}

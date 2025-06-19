package com.quizlet.explanations.databinding;

import android.view.View;
import androidx.constraintlayout.widget.ConstraintLayout;
import com.quizlet.partskit.widgets.QTextView;

/* loaded from: classes2.dex */
public final class o implements androidx.viewbinding.a {
    public final ConstraintLayout a;
    public final QTextView b;

    public o(ConstraintLayout constraintLayout, QTextView qTextView) {
        this.a = constraintLayout;
        this.b = qTextView;
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        return this.a;
    }
}

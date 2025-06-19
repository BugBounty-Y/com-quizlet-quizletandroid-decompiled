package com.quizlet.quizletandroid.ui.common.databinding;

import android.view.View;
import android.widget.ImageView;
import androidx.constraintlayout.widget.ConstraintLayout;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.uicommon.ui.common.views.QuizletPlusBadge;

/* loaded from: classes3.dex */
public final class e implements androidx.viewbinding.a {
    public final ConstraintLayout a;
    public final ImageView b;
    public final QTextView c;
    public final QuizletPlusBadge d;
    public final QTextView e;

    public e(ConstraintLayout constraintLayout, ImageView imageView, QTextView qTextView, QuizletPlusBadge quizletPlusBadge, QTextView qTextView2) {
        this.a = constraintLayout;
        this.b = imageView;
        this.c = qTextView;
        this.d = quizletPlusBadge;
        this.e = qTextView2;
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        return this.a;
    }
}

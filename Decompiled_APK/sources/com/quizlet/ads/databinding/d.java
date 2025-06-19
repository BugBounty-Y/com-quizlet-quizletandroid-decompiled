package com.quizlet.ads.databinding;

import android.view.View;
import android.widget.FrameLayout;
import androidx.constraintlayout.widget.ConstraintLayout;
import com.quizlet.partskit.widgets.QTextView;

/* loaded from: classes2.dex */
public final class d implements androidx.viewbinding.a {
    public final ConstraintLayout a;
    public final FrameLayout b;
    public final QTextView c;

    public d(FrameLayout frameLayout, ConstraintLayout constraintLayout, QTextView qTextView) {
        this.a = constraintLayout;
        this.b = frameLayout;
        this.c = qTextView;
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        return this.a;
    }
}

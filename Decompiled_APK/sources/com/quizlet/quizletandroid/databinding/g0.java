package com.quizlet.quizletandroid.databinding;

import android.view.View;
import android.widget.ProgressBar;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.recyclerview.widget.RecyclerView;
import com.quizlet.partskit.widgets.QButton;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.quizletandroid.ui.preview.SetPreviewOnboarding;

/* loaded from: classes3.dex */
public final class g0 implements androidx.viewbinding.a {
    public final ConstraintLayout a;
    public final QTextView b;
    public final QButton c;
    public final QButton d;
    public final SetPreviewOnboarding e;
    public final ProgressBar f;
    public final RecyclerView g;

    public g0(ConstraintLayout constraintLayout, QTextView qTextView, QButton qButton, QButton qButton2, SetPreviewOnboarding setPreviewOnboarding, ProgressBar progressBar, RecyclerView recyclerView) {
        this.a = constraintLayout;
        this.b = qTextView;
        this.c = qButton;
        this.d = qButton2;
        this.e = setPreviewOnboarding;
        this.f = progressBar;
        this.g = recyclerView;
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        return this.a;
    }
}

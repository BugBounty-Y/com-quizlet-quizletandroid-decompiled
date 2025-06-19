package com.quizlet.quizletandroid.databinding;

import android.view.View;
import androidx.constraintlayout.widget.ConstraintLayout;
import com.quizlet.partskit.widgets.QButton;
import com.quizlet.quizletandroid.ui.common.views.SimpleImageWithTextCardView;

/* loaded from: classes3.dex */
public final class E implements androidx.viewbinding.a {
    public final ConstraintLayout a;
    public final QButton b;
    public final SimpleImageWithTextCardView c;
    public final SimpleImageWithTextCardView d;
    public final SimpleImageWithTextCardView e;

    public E(ConstraintLayout constraintLayout, QButton qButton, SimpleImageWithTextCardView simpleImageWithTextCardView, SimpleImageWithTextCardView simpleImageWithTextCardView2, SimpleImageWithTextCardView simpleImageWithTextCardView3) {
        this.a = constraintLayout;
        this.b = qButton;
        this.c = simpleImageWithTextCardView;
        this.d = simpleImageWithTextCardView2;
        this.e = simpleImageWithTextCardView3;
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        return this.a;
    }
}

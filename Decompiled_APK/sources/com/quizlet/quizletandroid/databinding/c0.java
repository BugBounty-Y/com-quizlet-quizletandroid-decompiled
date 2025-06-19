package com.quizlet.quizletandroid.databinding;

import android.view.View;
import android.widget.ImageView;
import android.widget.RadioButton;
import com.quizlet.quizletandroid.ui.common.views.SquareFrameLayout;

/* loaded from: classes3.dex */
public final class c0 implements androidx.viewbinding.a {
    public final SquareFrameLayout a;
    public final RadioButton b;
    public final ImageView c;

    public c0(SquareFrameLayout squareFrameLayout, RadioButton radioButton, ImageView imageView) {
        this.a = squareFrameLayout;
        this.b = radioButton;
        this.c = imageView;
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        return this.a;
    }
}

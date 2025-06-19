package com.quizlet.assembly.databinding;

import android.view.View;
import android.widget.TextView;
import androidx.appcompat.widget.AppCompatImageView;

/* loaded from: classes2.dex */
public final class c implements androidx.viewbinding.a {
    public final com.quizlet.assembly.widgets.buttons.d a;
    public final AppCompatImageView b;
    public final AppCompatImageView c;
    public final TextView d;

    public c(com.quizlet.assembly.widgets.buttons.d dVar, AppCompatImageView appCompatImageView, AppCompatImageView appCompatImageView2, TextView textView) {
        this.a = dVar;
        this.b = appCompatImageView;
        this.c = appCompatImageView2;
        this.d = textView;
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        return this.a;
    }
}

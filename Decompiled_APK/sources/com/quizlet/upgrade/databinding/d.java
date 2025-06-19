package com.quizlet.upgrade.databinding;

import android.view.View;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.constraintlayout.widget.ConstraintLayout;

/* loaded from: classes3.dex */
public final class d implements androidx.viewbinding.a {
    public final ConstraintLayout a;
    public final TextView b;
    public final ImageView c;
    public final TextView d;

    public d(ConstraintLayout constraintLayout, TextView textView, ImageView imageView, TextView textView2) {
        this.a = constraintLayout;
        this.b = textView;
        this.c = imageView;
        this.d = textView2;
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        return this.a;
    }
}

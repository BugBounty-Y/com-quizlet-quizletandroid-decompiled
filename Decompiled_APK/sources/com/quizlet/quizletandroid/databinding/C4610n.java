package com.quizlet.quizletandroid.databinding;

import android.view.View;
import android.widget.FrameLayout;
import android.widget.ImageView;
import androidx.constraintlayout.widget.ConstraintLayout;
import com.quizlet.partskit.widgets.QTextView;

/* renamed from: com.quizlet.quizletandroid.databinding.n, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4610n implements androidx.viewbinding.a {
    public final ConstraintLayout a;
    public final FrameLayout b;
    public final ImageView c;
    public final FrameLayout d;
    public final View e;
    public final QTextView f;

    public C4610n(ConstraintLayout constraintLayout, FrameLayout frameLayout, ImageView imageView, FrameLayout frameLayout2, View view, QTextView qTextView) {
        this.a = constraintLayout;
        this.b = frameLayout;
        this.c = imageView;
        this.d = frameLayout2;
        this.e = view;
        this.f = qTextView;
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        return this.a;
    }
}

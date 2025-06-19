package com.quizlet.quizletandroid.ui.common.databinding;

import android.view.View;
import android.widget.FrameLayout;
import android.widget.ImageView;
import androidx.coordinatorlayout.widget.CoordinatorLayout;
import com.quizlet.partskit.widgets.QTextView;

/* loaded from: classes3.dex */
public final class a implements androidx.viewbinding.a {
    public final CoordinatorLayout a;
    public final FrameLayout b;
    public final ImageView c;
    public final FrameLayout d;
    public final QTextView e;

    public a(CoordinatorLayout coordinatorLayout, FrameLayout frameLayout, ImageView imageView, FrameLayout frameLayout2, QTextView qTextView) {
        this.a = coordinatorLayout;
        this.b = frameLayout;
        this.c = imageView;
        this.d = frameLayout2;
        this.e = qTextView;
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        return this.a;
    }
}

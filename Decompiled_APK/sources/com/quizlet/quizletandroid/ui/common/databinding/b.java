package com.quizlet.quizletandroid.ui.common.databinding;

import android.view.View;
import android.widget.ImageView;
import android.widget.LinearLayout;

/* loaded from: classes3.dex */
public final class b implements androidx.viewbinding.a {
    public final LinearLayout a;
    public final LinearLayout b;
    public final ImageView c;

    public b(LinearLayout linearLayout, LinearLayout linearLayout2, ImageView imageView) {
        this.a = linearLayout;
        this.b = linearLayout2;
        this.c = imageView;
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        return this.a;
    }
}

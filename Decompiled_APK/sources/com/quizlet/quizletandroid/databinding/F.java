package com.quizlet.quizletandroid.databinding;

import android.view.View;
import android.widget.ImageView;
import android.widget.LinearLayout;
import androidx.core.widget.NestedScrollView;

/* loaded from: classes3.dex */
public final class F implements androidx.viewbinding.a {
    public final NestedScrollView a;
    public final ImageView b;
    public final LinearLayout c;
    public final ImageView d;
    public final LinearLayout e;
    public final NestedScrollView f;

    public F(NestedScrollView nestedScrollView, ImageView imageView, LinearLayout linearLayout, ImageView imageView2, LinearLayout linearLayout2, NestedScrollView nestedScrollView2) {
        this.a = nestedScrollView;
        this.b = imageView;
        this.c = linearLayout;
        this.d = imageView2;
        this.e = linearLayout2;
        this.f = nestedScrollView2;
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        return this.a;
    }
}

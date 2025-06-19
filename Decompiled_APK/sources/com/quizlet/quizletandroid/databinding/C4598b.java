package com.quizlet.quizletandroid.databinding;

import android.view.View;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import com.quizlet.quizletandroid.ui.common.views.LoadingIndicatorView;

/* renamed from: com.quizlet.quizletandroid.databinding.b, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4598b implements androidx.viewbinding.a {
    public final LinearLayout a;
    public final ImageView b;
    public final FrameLayout c;
    public final LoadingIndicatorView d;
    public final FrameLayout e;

    public C4598b(LinearLayout linearLayout, ImageView imageView, FrameLayout frameLayout, LoadingIndicatorView loadingIndicatorView, FrameLayout frameLayout2) {
        this.a = linearLayout;
        this.b = imageView;
        this.c = frameLayout;
        this.d = loadingIndicatorView;
        this.e = frameLayout2;
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        return this.a;
    }
}

package com.quizlet.quizletandroid.databinding;

import android.view.View;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import androidx.compose.ui.platform.ComposeView;
import com.airbnb.lottie.LottieAnimationView;

/* renamed from: com.quizlet.quizletandroid.databinding.m, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4609m implements androidx.viewbinding.a {
    public final FrameLayout a;
    public final LottieAnimationView b;
    public final FrameLayout c;
    public final LinearLayout d;
    public final ComposeView e;
    public final ProgressBar f;
    public final ComposeView g;
    public final ComposeView h;

    public C4609m(FrameLayout frameLayout, LottieAnimationView lottieAnimationView, FrameLayout frameLayout2, LinearLayout linearLayout, ComposeView composeView, ProgressBar progressBar, ComposeView composeView2, ComposeView composeView3) {
        this.a = frameLayout;
        this.b = lottieAnimationView;
        this.c = frameLayout2;
        this.d = linearLayout;
        this.e = composeView;
        this.f = progressBar;
        this.g = composeView2;
        this.h = composeView3;
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        return this.a;
    }
}

package com.quizlet.quizletandroid.databinding;

import android.view.View;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import androidx.appcompat.widget.Toolbar;
import com.google.android.material.appbar.AppBarLayout;
import com.quizlet.partskit.widgets.QButton;
import com.quizlet.ui.webview.QuizletWebView;

/* renamed from: com.quizlet.quizletandroid.databinding.k, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4607k implements androidx.viewbinding.a {
    public final LinearLayout a;
    public final AppBarLayout b;
    public final QButton c;
    public final ProgressBar d;
    public final Toolbar e;
    public final QuizletWebView f;

    public C4607k(LinearLayout linearLayout, AppBarLayout appBarLayout, QButton qButton, ProgressBar progressBar, Toolbar toolbar, QuizletWebView quizletWebView) {
        this.a = linearLayout;
        this.b = appBarLayout;
        this.c = qButton;
        this.d = progressBar;
        this.e = toolbar;
        this.f = quizletWebView;
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        return this.a;
    }
}

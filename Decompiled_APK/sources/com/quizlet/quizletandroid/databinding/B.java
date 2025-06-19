package com.quizlet.quizletandroid.databinding;

import android.view.View;
import androidx.recyclerview.widget.RecyclerView;
import com.quizlet.partskit.widgets.QButton;
import com.quizlet.partskit.widgets.QProgressBar;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.quizletandroid.ui.common.views.ShareSetButton;

/* loaded from: classes3.dex */
public final class B implements androidx.viewbinding.a {
    public final View a;
    public final View b;
    public final QTextView c;
    public final QTextView d;
    public final QTextView e;
    public final RecyclerView f;
    public final View g;
    public final QTextView h;
    public final QButton i;
    public final QButton j;
    public final QProgressBar k;
    public final ShareSetButton l;

    public B(View view, View view2, QTextView qTextView, QTextView qTextView2, QTextView qTextView3, RecyclerView recyclerView, View view3, QTextView qTextView4, QButton qButton, QButton qButton2, QProgressBar qProgressBar, ShareSetButton shareSetButton) {
        this.a = view;
        this.b = view2;
        this.c = qTextView;
        this.d = qTextView2;
        this.e = qTextView3;
        this.f = recyclerView;
        this.g = view3;
        this.h = qTextView4;
        this.i = qButton;
        this.j = qButton2;
        this.k = qProgressBar;
        this.l = shareSetButton;
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        return this.a;
    }
}

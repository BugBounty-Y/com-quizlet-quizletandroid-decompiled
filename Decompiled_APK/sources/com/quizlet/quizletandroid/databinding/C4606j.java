package com.quizlet.quizletandroid.databinding;

import android.view.View;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import androidx.constraintlayout.widget.ConstraintLayout;
import com.quizlet.partskit.widgets.QProgressBar;
import com.quizlet.partskit.widgets.QTextView;

/* renamed from: com.quizlet.quizletandroid.databinding.j, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4606j implements androidx.viewbinding.a {
    public final LinearLayout a;
    public final FrameLayout b;
    public final FrameLayout c;
    public final LinearLayout d;
    public final QProgressBar e;
    public final QTextView f;
    public final ConstraintLayout g;

    public C4606j(LinearLayout linearLayout, FrameLayout frameLayout, FrameLayout frameLayout2, LinearLayout linearLayout2, QProgressBar qProgressBar, QTextView qTextView, ConstraintLayout constraintLayout) {
        this.a = linearLayout;
        this.b = frameLayout;
        this.c = frameLayout2;
        this.d = linearLayout2;
        this.e = qProgressBar;
        this.f = qTextView;
        this.g = constraintLayout;
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        return this.a;
    }
}

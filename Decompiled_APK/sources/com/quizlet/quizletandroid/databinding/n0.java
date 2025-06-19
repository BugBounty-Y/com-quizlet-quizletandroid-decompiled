package com.quizlet.quizletandroid.databinding;

import android.view.View;
import android.widget.LinearLayout;
import com.quizlet.partskit.widgets.QButton;
import com.quizlet.partskit.widgets.QTextView;

/* loaded from: classes3.dex */
public final class n0 implements androidx.viewbinding.a {
    public final LinearLayout a;
    public final QButton b;
    public final QButton c;
    public final QTextView d;

    public n0(LinearLayout linearLayout, QButton qButton, QButton qButton2, QTextView qTextView) {
        this.a = linearLayout;
        this.b = qButton;
        this.c = qButton2;
        this.d = qTextView;
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        return this.a;
    }
}

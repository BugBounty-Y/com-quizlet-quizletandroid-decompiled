package com.quizlet.quizletandroid.databinding;

import android.view.View;
import android.widget.LinearLayout;
import com.quizlet.partskit.widgets.QTextView;

/* loaded from: classes3.dex */
public final class m0 implements androidx.viewbinding.a {
    public final LinearLayout a;
    public final View b;
    public final QTextView c;

    public m0(LinearLayout linearLayout, View view, QTextView qTextView) {
        this.a = linearLayout;
        this.b = view;
        this.c = qTextView;
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        return this.a;
    }
}

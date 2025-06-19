package com.quizlet.quizletandroid.databinding;

import android.view.View;
import android.widget.LinearLayout;
import com.quizlet.partskit.widgets.QTextView;

/* loaded from: classes3.dex */
public final class M implements androidx.viewbinding.a {
    public final LinearLayout a;
    public final QTextView b;
    public final LinearLayout c;
    public final QTextView d;

    public M(LinearLayout linearLayout, QTextView qTextView, LinearLayout linearLayout2, QTextView qTextView2) {
        this.a = linearLayout;
        this.b = qTextView;
        this.c = linearLayout2;
        this.d = qTextView2;
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        return this.a;
    }
}

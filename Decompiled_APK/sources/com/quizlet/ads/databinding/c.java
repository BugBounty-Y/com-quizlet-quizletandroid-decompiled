package com.quizlet.ads.databinding;

import android.view.View;
import android.widget.FrameLayout;
import androidx.constraintlayout.widget.ConstraintLayout;
import com.quizlet.partskit.widgets.QTextView;

/* loaded from: classes2.dex */
public final class c implements androidx.viewbinding.a {
    public final ConstraintLayout a;
    public final QTextView b;
    public final FrameLayout c;

    public c(FrameLayout frameLayout, ConstraintLayout constraintLayout, QTextView qTextView) {
        this.a = constraintLayout;
        this.b = qTextView;
        this.c = frameLayout;
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        return this.a;
    }
}

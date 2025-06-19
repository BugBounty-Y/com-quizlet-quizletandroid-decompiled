package com.quizlet.quizletandroid.databinding;

import android.view.View;
import androidx.constraintlayout.widget.ConstraintLayout;
import com.quizlet.partskit.widgets.QTextView;

/* loaded from: classes3.dex */
public final class o0 implements androidx.viewbinding.a {
    public final /* synthetic */ int a;
    public final ConstraintLayout b;
    public final QTextView c;
    public final View d;

    public /* synthetic */ o0(ConstraintLayout constraintLayout, QTextView qTextView, View view, int i) {
        this.a = i;
        this.b = constraintLayout;
        this.c = qTextView;
        this.d = view;
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        switch (this.a) {
        }
        return this.b;
    }
}

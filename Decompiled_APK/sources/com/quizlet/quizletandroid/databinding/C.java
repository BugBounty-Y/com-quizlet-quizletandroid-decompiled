package com.quizlet.quizletandroid.databinding;

import android.view.View;
import android.widget.FrameLayout;
import androidx.constraintlayout.widget.ConstraintLayout;
import com.quizlet.partskit.widgets.QButton;

/* loaded from: classes3.dex */
public final class C implements androidx.viewbinding.a {
    public final ConstraintLayout a;
    public final FrameLayout b;
    public final QButton c;
    public final QButton d;

    public C(ConstraintLayout constraintLayout, FrameLayout frameLayout, QButton qButton, QButton qButton2) {
        this.a = constraintLayout;
        this.b = frameLayout;
        this.c = qButton;
        this.d = qButton2;
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        return this.a;
    }
}

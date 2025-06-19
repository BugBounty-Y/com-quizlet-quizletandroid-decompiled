package com.quizlet.quizletandroid.databinding;

import android.view.View;
import androidx.constraintlayout.widget.ConstraintLayout;
import com.quizlet.partskit.widgets.QButton;

/* loaded from: classes3.dex */
public final class d0 implements androidx.viewbinding.a {
    public final ConstraintLayout a;
    public final QButton b;
    public final QButton c;

    public d0(ConstraintLayout constraintLayout, QButton qButton, QButton qButton2) {
        this.a = constraintLayout;
        this.b = qButton;
        this.c = qButton2;
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        return this.a;
    }
}

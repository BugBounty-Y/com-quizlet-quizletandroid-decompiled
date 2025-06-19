package com.quizlet.quizletandroid.ui.common.databinding;

import android.view.View;
import android.widget.FrameLayout;
import androidx.constraintlayout.widget.ConstraintLayout;

/* loaded from: classes3.dex */
public final class d implements androidx.viewbinding.a {
    public final ConstraintLayout a;
    public final FrameLayout b;

    public d(ConstraintLayout constraintLayout, FrameLayout frameLayout) {
        this.a = constraintLayout;
        this.b = frameLayout;
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        return this.a;
    }
}

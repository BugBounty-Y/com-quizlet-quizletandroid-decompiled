package com.quizlet.ads.databinding;

import android.view.View;
import android.widget.FrameLayout;
import androidx.constraintlayout.widget.ConstraintLayout;

/* loaded from: classes2.dex */
public final class e implements androidx.viewbinding.a {
    public final ConstraintLayout a;
    public final FrameLayout b;
    public final FrameLayout c;

    public e(ConstraintLayout constraintLayout, FrameLayout frameLayout, FrameLayout frameLayout2) {
        this.a = constraintLayout;
        this.b = frameLayout;
        this.c = frameLayout2;
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        return this.a;
    }
}

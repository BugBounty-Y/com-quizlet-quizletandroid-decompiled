package com.quizlet.quizletandroid.databinding;

import android.view.View;
import android.widget.LinearLayout;
import com.quizlet.quizletandroid.ui.common.views.ToggleSwipeableViewPager;

/* renamed from: com.quizlet.quizletandroid.databinding.c, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4599c implements androidx.viewbinding.a {
    public final LinearLayout a;
    public final ToggleSwipeableViewPager b;
    public final com.quizlet.features.infra.legacyadapter.databinding.h c;

    public C4599c(LinearLayout linearLayout, ToggleSwipeableViewPager toggleSwipeableViewPager, com.quizlet.features.infra.legacyadapter.databinding.h hVar) {
        this.a = linearLayout;
        this.b = toggleSwipeableViewPager;
        this.c = hVar;
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        return this.a;
    }
}

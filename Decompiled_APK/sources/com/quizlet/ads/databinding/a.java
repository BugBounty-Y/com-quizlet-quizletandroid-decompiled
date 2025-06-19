package com.quizlet.ads.databinding;

import android.view.View;
import android.widget.FrameLayout;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.fragment.app.FragmentContainerView;
import com.quizlet.ads.ui.widgets.AdsCountDownButton;

/* loaded from: classes2.dex */
public final class a implements androidx.viewbinding.a {
    public final ConstraintLayout a;
    public final FragmentContainerView b;
    public final AdsCountDownButton c;
    public final FrameLayout d;

    public a(ConstraintLayout constraintLayout, FragmentContainerView fragmentContainerView, AdsCountDownButton adsCountDownButton, FrameLayout frameLayout) {
        this.a = constraintLayout;
        this.b = fragmentContainerView;
        this.c = adsCountDownButton;
        this.d = frameLayout;
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        return this.a;
    }
}

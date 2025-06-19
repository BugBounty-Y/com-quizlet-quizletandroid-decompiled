package com.quizlet.features.setpage.databinding;

import android.view.View;
import android.widget.FrameLayout;
import android.widget.ProgressBar;
import androidx.compose.ui.platform.ComposeView;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.coordinatorlayout.widget.CoordinatorLayout;
import com.google.android.material.appbar.AppBarLayout;
import com.quizlet.features.achievements.achievement.AchievementEarnedView;
import com.quizlet.partskit.widgets.QButton;
import com.quizlet.uicommon.ui.common.views.SimpleGradientView;

/* loaded from: classes3.dex */
public final class a implements androidx.viewbinding.a {
    public final ConstraintLayout a;
    public final AchievementEarnedView b;
    public final SimpleGradientView c;
    public final AppBarLayout d;
    public final FrameLayout e;
    public final FrameLayout f;
    public final FrameLayout g;
    public final FrameLayout h;
    public final FrameLayout i;
    public final ComposeView j;
    public final ProgressBar k;
    public final FrameLayout l;
    public final QButton m;
    public final FrameLayout n;
    public final View o;
    public final CoordinatorLayout p;
    public final FrameLayout q;
    public final ComposeView r;

    public a(ConstraintLayout constraintLayout, AchievementEarnedView achievementEarnedView, SimpleGradientView simpleGradientView, AppBarLayout appBarLayout, FrameLayout frameLayout, FrameLayout frameLayout2, FrameLayout frameLayout3, FrameLayout frameLayout4, FrameLayout frameLayout5, ComposeView composeView, ProgressBar progressBar, FrameLayout frameLayout6, QButton qButton, FrameLayout frameLayout7, View view, CoordinatorLayout coordinatorLayout, FrameLayout frameLayout8, ComposeView composeView2) {
        this.a = constraintLayout;
        this.b = achievementEarnedView;
        this.c = simpleGradientView;
        this.d = appBarLayout;
        this.e = frameLayout;
        this.f = frameLayout2;
        this.g = frameLayout3;
        this.h = frameLayout4;
        this.i = frameLayout5;
        this.j = composeView;
        this.k = progressBar;
        this.l = frameLayout6;
        this.m = qButton;
        this.n = frameLayout7;
        this.o = view;
        this.p = coordinatorLayout;
        this.q = frameLayout8;
        this.r = composeView2;
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        return this.a;
    }
}

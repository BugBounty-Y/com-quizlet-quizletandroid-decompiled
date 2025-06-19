package com.quizlet.quizletandroid.databinding;

import android.view.View;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.appcompat.widget.Toolbar;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.constraintlayout.widget.Group;
import androidx.coordinatorlayout.widget.CoordinatorLayout;
import com.quizlet.features.achievements.achievement.AchievementEarnedView;
import com.quizlet.partskit.widgets.QTabLayout;
import com.quizlet.quizletandroid.ui.common.views.ToggleSwipeableViewPager;

/* loaded from: classes3.dex */
public final class D implements androidx.viewbinding.a {
    public final CoordinatorLayout a;
    public final AchievementEarnedView b;
    public final Group c;
    public final ConstraintLayout d;
    public final ToggleSwipeableViewPager e;
    public final ImageView f;
    public final QTabLayout g;
    public final Toolbar h;
    public final TextView i;
    public final ImageView j;
    public final TextView k;

    public D(CoordinatorLayout coordinatorLayout, AchievementEarnedView achievementEarnedView, Group group, ConstraintLayout constraintLayout, ToggleSwipeableViewPager toggleSwipeableViewPager, ImageView imageView, QTabLayout qTabLayout, Toolbar toolbar, TextView textView, ImageView imageView2, TextView textView2) {
        this.a = coordinatorLayout;
        this.b = achievementEarnedView;
        this.c = group;
        this.d = constraintLayout;
        this.e = toggleSwipeableViewPager;
        this.f = imageView;
        this.g = qTabLayout;
        this.h = toolbar;
        this.i = textView;
        this.j = imageView2;
        this.k = textView2;
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        return this.a;
    }
}

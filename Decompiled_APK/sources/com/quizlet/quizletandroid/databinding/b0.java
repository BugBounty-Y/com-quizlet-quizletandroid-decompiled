package com.quizlet.quizletandroid.databinding;

import android.view.View;
import android.widget.FrameLayout;
import android.widget.ProgressBar;
import androidx.compose.ui.platform.ComposeView;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.coordinatorlayout.widget.CoordinatorLayout;
import androidx.recyclerview.widget.RecyclerView;
import androidx.swiperefreshlayout.widget.SwipeRefreshLayout;
import com.quizlet.features.achievements.achievement.AchievementEarnedView;

/* loaded from: classes3.dex */
public final class b0 implements androidx.viewbinding.a {
    public final ConstraintLayout a;
    public final AchievementEarnedView b;
    public final FrameLayout c;
    public final ProgressBar d;
    public final CoordinatorLayout e;
    public final SwipeRefreshLayout f;
    public final ComposeView g;
    public final RecyclerView h;

    public b0(ConstraintLayout constraintLayout, AchievementEarnedView achievementEarnedView, FrameLayout frameLayout, ProgressBar progressBar, CoordinatorLayout coordinatorLayout, SwipeRefreshLayout swipeRefreshLayout, ComposeView composeView, RecyclerView recyclerView) {
        this.a = constraintLayout;
        this.b = achievementEarnedView;
        this.c = frameLayout;
        this.d = progressBar;
        this.e = coordinatorLayout;
        this.f = swipeRefreshLayout;
        this.g = composeView;
        this.h = recyclerView;
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        return this.a;
    }
}

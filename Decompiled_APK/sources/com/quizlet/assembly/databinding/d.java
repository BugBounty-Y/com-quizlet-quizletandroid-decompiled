package com.quizlet.assembly.databinding;

import android.view.View;
import androidx.compose.ui.platform.ComposeView;
import com.quizlet.features.achievements.achievement.AchievementEarnedView;

/* loaded from: classes2.dex */
public final class d implements androidx.viewbinding.a {
    public final AchievementEarnedView a;
    public final ComposeView b;

    public d(AchievementEarnedView achievementEarnedView, ComposeView composeView) {
        this.a = achievementEarnedView;
        this.b = composeView;
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        return this.a;
    }
}

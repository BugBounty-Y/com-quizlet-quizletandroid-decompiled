package com.quizlet.features.achievements.achievement;

import android.view.View;
import android.view.animation.Animation;
import com.quizlet.partskit.widgets.QProgressBar;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class f implements Animation.AnimationListener {
    public final /* synthetic */ int a;
    public final /* synthetic */ View b;

    public /* synthetic */ f(View view, int i) {
        this.a = i;
        this.b = view;
    }

    private final void a(Animation animation) {
    }

    private final void b(Animation animation) {
    }

    private final void c(Animation animation) {
    }

    private final void d(Animation animation) {
    }

    @Override // android.view.animation.Animation.AnimationListener
    public final void onAnimationEnd(Animation animation) {
        View view = this.b;
        switch (this.a) {
            case 0:
                int i = AchievementEarnedView.s;
                AchievementEarnedView achievementEarnedView = ((AchievementEarnedView) view).r.a;
                Intrinsics.checkNotNullExpressionValue(achievementEarnedView, "getRoot(...)");
                achievementEarnedView.setVisibility(8);
                break;
            default:
                ((QProgressBar) view).a = null;
                break;
        }
    }

    @Override // android.view.animation.Animation.AnimationListener
    public final void onAnimationRepeat(Animation animation) {
        int i = this.a;
    }

    @Override // android.view.animation.Animation.AnimationListener
    public final void onAnimationStart(Animation animation) {
        int i = this.a;
    }
}

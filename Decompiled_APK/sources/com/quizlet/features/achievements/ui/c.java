package com.quizlet.features.achievements.ui;

import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final /* synthetic */ class c implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ AchievementsFragment b;

    public /* synthetic */ c(AchievementsFragment achievementsFragment, int i) {
        this.a = i;
        this.b = achievementsFragment;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        AchievementsFragment achievementsFragment = this.b;
        switch (this.a) {
            case 0:
                String str = AchievementsFragment.l;
                return new com.quizlet.baseui.compose.b(new androidx.compose.runtime.internal.d(true, 313074805, new com.quizlet.assembly.compose.cards.c(achievementsFragment, 9)));
            default:
                String str2 = AchievementsFragment.l;
                androidx.lifecycle.viewmodel.c defaultViewModelCreationExtras = achievementsFragment.getDefaultViewModelCreationExtras();
                Intrinsics.checkNotNullExpressionValue(defaultViewModelCreationExtras, "<get-defaultViewModelCreationExtras>(...)");
                return defaultViewModelCreationExtras;
        }
    }
}

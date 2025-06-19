package com.quizlet.features.setpage;

import androidx.compose.ui.platform.ComposeView;
import androidx.coordinatorlayout.widget.CoordinatorLayout;
import androidx.lifecycle.p0;
import com.google.android.material.appbar.AppBarLayout;
import com.quizlet.features.achievements.achievement.AchievementEarnedView;
import com.quizlet.features.infra.basestudy.data.models.v;
import com.quizlet.features.setpage.viewmodel.I;
import com.quizlet.features.setpage.viewmodel.P;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.E;

/* loaded from: classes3.dex */
public final /* synthetic */ class i implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ r b;

    public /* synthetic */ i(r rVar, int i) {
        this.a = i;
        this.b = rVar;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        r rVar = this.b;
        switch (this.a) {
            case 0:
                AppBarLayout layoutCollapsingAppbar = ((com.quizlet.features.setpage.databinding.a) rVar.K()).d;
                Intrinsics.checkNotNullExpressionValue(layoutCollapsingAppbar, "layoutCollapsingAppbar");
                break;
            case 1:
                AchievementEarnedView achievementToast = ((com.quizlet.features.setpage.databinding.a) rVar.K()).b;
                Intrinsics.checkNotNullExpressionValue(achievementToast, "achievementToast");
                break;
            case 2:
                ComposeView setpageHeaderSubscriptionAd = ((com.quizlet.features.setpage.databinding.a) rVar.K()).j;
                Intrinsics.checkNotNullExpressionValue(setpageHeaderSubscriptionAd, "setpageHeaderSubscriptionAd");
                break;
            case 3:
                break;
            case 4:
                break;
            case 5:
                break;
            case 6:
                break;
            case 7:
                break;
            case 8:
                break;
            case 9:
                CoordinatorLayout snackbarLayoutWrapper = ((com.quizlet.features.setpage.databinding.a) rVar.K()).p;
                Intrinsics.checkNotNullExpressionValue(snackbarLayoutWrapper, "snackbarLayoutWrapper");
                break;
            case 10:
                break;
            case 11:
                P pR = rVar.R();
                pR.getClass();
                E.A(p0.j(pR), pR.J1, null, new I(pR, true, null), 2);
                break;
            case 12:
                rVar.R().C1 = false;
                break;
            default:
                String str = r.c1;
                P pR2 = rVar.R();
                pR2.X.j(Boolean.FALSE);
                pR2.f.A("set_page_ad_load_failure_upsell_ad_clicked");
                pR2.i1.j(v.a);
                break;
        }
        return Unit.a;
    }
}

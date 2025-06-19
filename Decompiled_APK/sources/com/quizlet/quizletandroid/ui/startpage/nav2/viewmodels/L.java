package com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels;

import androidx.lifecycle.X;
import com.quizlet.assembly.compose.buttons.Z;
import com.quizlet.data.model.EnumC4164s0;
import com.quizlet.eventlogger.EventLogger;
import com.quizlet.eventlogger.EventLoggerExt;
import com.quizlet.eventlogger.features.qincentives.QIncentivesEventLogger;
import com.quizlet.eventlogger.features.revisioncenter.RevisionCenterLogger;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.flow.d0;
import kotlinx.coroutines.flow.e0;

@Metadata
/* loaded from: classes3.dex */
public final class L extends com.quizlet.viewmodel.b {
    public final com.quizlet.login.common.interactors.d c;
    public final com.quizlet.infra.legacysyncengine.managers.d d;
    public final androidx.work.impl.model.c e;
    public final com.quizlet.featuregate.features.home.a f;
    public final com.quizlet.data.interactor.course.a g;
    public final com.quizlet.quizletandroid.ui.startpage.nav2.logging.c h;
    public final com.quizlet.quizletandroid.ui.startpage.nav2.logging.a i;
    public final com.quizlet.data.interactor.achievements.f j;
    public final RevisionCenterLogger k;
    public final com.quizlet.data.repository.folderwithcreatorinclass.e l;
    public final QIncentivesEventLogger m;
    public final com.google.android.gms.measurement.internal.J n;
    public final com.features.flashcards.creatormarketing.o o;
    public final d0 p;
    public final d0 q;
    public final X r;
    public final X s;

    public L(com.quizlet.login.common.interactors.d deepLinkRouter, com.quizlet.infra.legacysyncengine.managers.d loggedInUserManager, androidx.work.impl.model.c userProperties, com.quizlet.featuregate.features.home.a activityCenterFeature, com.quizlet.data.repository.classfolder.e marketingAnalyticsManager, com.quizlet.data.interactor.course.a edgyLogger, com.quizlet.quizletandroid.ui.startpage.nav2.logging.c homeNavigationEventLogger, com.quizlet.quizletandroid.ui.startpage.nav2.logging.a homeEventLogger, com.quizlet.data.interactor.achievements.f subjectLogger, RevisionCenterLogger revisionCenterLogger, com.quizlet.data.repository.folderwithcreatorinclass.e qIncentivesUseCase, QIncentivesEventLogger qIncentivesEventLogger, com.google.android.gms.measurement.internal.J onboardingELLPresentationUseCase, com.features.flashcards.creatormarketing.o shouldShowCreatorMarketingModalUseCase) {
        Intrinsics.checkNotNullParameter(deepLinkRouter, "deepLinkRouter");
        Intrinsics.checkNotNullParameter(loggedInUserManager, "loggedInUserManager");
        Intrinsics.checkNotNullParameter(userProperties, "userProperties");
        Intrinsics.checkNotNullParameter(activityCenterFeature, "activityCenterFeature");
        Intrinsics.checkNotNullParameter(marketingAnalyticsManager, "marketingAnalyticsManager");
        Intrinsics.checkNotNullParameter(edgyLogger, "edgyLogger");
        Intrinsics.checkNotNullParameter(homeNavigationEventLogger, "homeNavigationEventLogger");
        Intrinsics.checkNotNullParameter(homeEventLogger, "homeEventLogger");
        Intrinsics.checkNotNullParameter(subjectLogger, "subjectLogger");
        Intrinsics.checkNotNullParameter(revisionCenterLogger, "revisionCenterLogger");
        Intrinsics.checkNotNullParameter(qIncentivesUseCase, "qIncentivesUseCase");
        Intrinsics.checkNotNullParameter(qIncentivesEventLogger, "qIncentivesEventLogger");
        Intrinsics.checkNotNullParameter(onboardingELLPresentationUseCase, "onboardingELLPresentationUseCase");
        Intrinsics.checkNotNullParameter(shouldShowCreatorMarketingModalUseCase, "shouldShowCreatorMarketingModalUseCase");
        this.c = deepLinkRouter;
        this.d = loggedInUserManager;
        this.e = userProperties;
        this.f = activityCenterFeature;
        this.g = edgyLogger;
        this.h = homeNavigationEventLogger;
        this.i = homeEventLogger;
        this.j = subjectLogger;
        this.k = revisionCenterLogger;
        this.l = qIncentivesUseCase;
        this.m = qIncentivesEventLogger;
        this.n = onboardingELLPresentationUseCase;
        this.o = shouldShowCreatorMarketingModalUseCase;
        this.p = e0.b(0, 1, null, 5);
        this.q = e0.b(0, 1, null, 5);
        this.r = new X(1);
        this.s = new X(1);
        marketingAnalyticsManager.p(new com.braze.requests.framework.o(marketingAnalyticsManager, 19));
    }

    public static void C(L l) {
        EventLoggerExt.a((EventLogger) l.g.b, "course_empty_state_home_did_tap_add_course", new Z(5));
        l.p.h(new Q());
    }

    public final void B(EnumC4164s0 enumC4164s0) {
        this.p.h(new C4747p(enumC4164s0));
    }
}

package com.quizlet.features.userprofile.data;

import androidx.lifecycle.p0;
import androidx.lifecycle.w0;
import com.quizlet.features.userprofile.ui.UserProfileFragment;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C5041z;
import kotlinx.coroutines.E;
import kotlinx.coroutines.flow.d0;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.flow.s0;

@Metadata
/* loaded from: classes3.dex */
public final class x extends w0 {
    public final com.quizlet.quizletandroid.interactor.t b;
    public final com.google.firebase.messaging.p c;
    public final com.quizlet.infra.legacysyncengine.managers.d d;
    public final com.google.mlkit.common.sdkinternal.model.a e;
    public final com.quizlet.features.userprofile.a f;
    public final androidx.work.impl.model.e g;
    public final com.quizlet.featuregate.features.home.a h;
    public final com.lyft.android.scissors.b i;
    public final androidx.work.impl.model.c j;
    public final s0 k;
    public final d0 l;
    public final d0 m;

    public x(com.quizlet.quizletandroid.interactor.t loggedInUserInteractor, com.google.firebase.messaging.p achievementsUseCase, com.quizlet.infra.legacysyncengine.managers.d loggedInUserManager, com.google.mlkit.common.sdkinternal.model.a achievementsStreakDataProvider, com.quizlet.features.userprofile.a eventLogger, com.quizlet.quizletandroid.braze.events.b brazeViewScreenEventManager, androidx.work.impl.model.e userHasFreeTrialUseCase, com.quizlet.featuregate.features.home.a activityCenterFeature, com.lyft.android.scissors.b getActivityCenterUnreadCountUseCase, androidx.work.impl.model.c userProperties) {
        Intrinsics.checkNotNullParameter(loggedInUserInteractor, "loggedInUserInteractor");
        Intrinsics.checkNotNullParameter(achievementsUseCase, "achievementsUseCase");
        Intrinsics.checkNotNullParameter(loggedInUserManager, "loggedInUserManager");
        Intrinsics.checkNotNullParameter(achievementsStreakDataProvider, "achievementsStreakDataProvider");
        Intrinsics.checkNotNullParameter(eventLogger, "eventLogger");
        Intrinsics.checkNotNullParameter(brazeViewScreenEventManager, "brazeViewScreenEventManager");
        Intrinsics.checkNotNullParameter(userHasFreeTrialUseCase, "userHasFreeTrialUseCase");
        Intrinsics.checkNotNullParameter(activityCenterFeature, "activityCenterFeature");
        Intrinsics.checkNotNullParameter(getActivityCenterUnreadCountUseCase, "getActivityCenterUnreadCountUseCase");
        Intrinsics.checkNotNullParameter(userProperties, "userProperties");
        this.b = loggedInUserInteractor;
        this.c = achievementsUseCase;
        this.d = loggedInUserManager;
        this.e = achievementsStreakDataProvider;
        this.f = eventLogger;
        this.g = userHasFreeTrialUseCase;
        this.h = activityCenterFeature;
        this.i = getActivityCenterUnreadCountUseCase;
        this.j = userProperties;
        this.k = e0.c(i.a);
        this.l = e0.b(0, 0, null, 7);
        this.m = e0.b(0, 0, null, 7);
        E.A(p0.j(this), new androidx.compose.ui.text.font.o(C5041z.a, 9), null, new n(this, null), 2);
        brazeViewScreenEventManager.a(UserProfileFragment.k);
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0016  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object A(com.quizlet.features.userprofile.data.x r5, kotlin.coroutines.jvm.internal.c r6) {
        /*
            r5.getClass()
            boolean r0 = r6 instanceof com.quizlet.features.userprofile.data.l
            if (r0 == 0) goto L16
            r0 = r6
            com.quizlet.features.userprofile.data.l r0 = (com.quizlet.features.userprofile.data.l) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L16
            int r1 = r1 - r2
            r0.m = r1
            goto L1b
        L16:
            com.quizlet.features.userprofile.data.l r0 = new com.quizlet.features.userprofile.data.l
            r0.<init>(r5, r6)
        L1b:
            java.lang.Object r6 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 2
            r4 = 1
            if (r2 == 0) goto L3b
            if (r2 == r4) goto L35
            if (r2 != r3) goto L2d
            androidx.glance.appwidget.protobuf.Z.e(r6)
            return r6
        L2d:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L35:
            com.quizlet.features.userprofile.data.x r5 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L4d
        L3b:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            r0.j = r5
            r0.m = r4
            com.quizlet.featuregate.features.home.a r6 = r5.h
            androidx.work.impl.model.c r2 = r5.j
            java.lang.Object r6 = r6.a(r2, r0)
            if (r6 != r1) goto L4d
            goto L62
        L4d:
            java.lang.Boolean r6 = (java.lang.Boolean) r6
            boolean r6 = r6.booleanValue()
            if (r6 == 0) goto L64
            com.lyft.android.scissors.b r5 = r5.i
            r6 = 0
            r0.j = r6
            r0.m = r3
            java.lang.Object r5 = r5.a(r0)
            if (r5 != r1) goto L63
        L62:
            return r1
        L63:
            return r5
        L64:
            java.lang.Integer r5 = new java.lang.Integer
            r6 = 0
            r5.<init>(r6)
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.userprofile.data.x.A(com.quizlet.features.userprofile.data.x, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }
}

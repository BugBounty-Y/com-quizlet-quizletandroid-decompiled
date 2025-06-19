package com.quizlet.features.achievements.viewmodel;

import androidx.lifecycle.m0;
import androidx.lifecycle.p0;
import androidx.lifecycle.w0;
import com.google.firebase.crashlytics.internal.common.j;
import com.onetrust.otpublishers.headless.Internal.Helper.h;
import com.quizlet.data.interactor.achievements.f;
import com.quizlet.edgy.ui.viewmodel.C4203d;
import com.quizlet.eventlogger.features.achievements.AchievementsEventLog;
import com.quizlet.eventlogger.features.achievements.AchievementsEventLogger;
import com.quizlet.features.achievements.data.d;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.E;
import kotlinx.coroutines.flow.d0;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.flow.s0;

@Metadata
/* loaded from: classes2.dex */
public final class b extends w0 implements c {
    public final h b;
    public final com.google.android.material.floatingactionbutton.c c;
    public final f d;
    public final dagger.internal.a e;
    public final j f;
    public final s0 g;
    public final String h;
    public final d0 i;

    public b(h achievementsDataProvider, com.google.android.material.floatingactionbutton.c achievementsRecentsUseCase, f achievementBadgesUseCase, dagger.internal.a achievementsEventLogger, j getAchievementsBadgeByIdUseCase, m0 savedStateHandle) {
        Intrinsics.checkNotNullParameter(achievementsDataProvider, "achievementsDataProvider");
        Intrinsics.checkNotNullParameter(achievementsRecentsUseCase, "achievementsRecentsUseCase");
        Intrinsics.checkNotNullParameter(achievementBadgesUseCase, "achievementBadgesUseCase");
        Intrinsics.checkNotNullParameter(achievementsEventLogger, "achievementsEventLogger");
        Intrinsics.checkNotNullParameter(getAchievementsBadgeByIdUseCase, "getAchievementsBadgeByIdUseCase");
        Intrinsics.checkNotNullParameter(savedStateHandle, "savedStateHandle");
        this.b = achievementsDataProvider;
        this.c = achievementsRecentsUseCase;
        this.d = achievementBadgesUseCase;
        this.e = achievementsEventLogger;
        this.f = getAchievementsBadgeByIdUseCase;
        this.g = e0.c(com.quizlet.features.achievements.data.f.a);
        this.h = (String) savedStateHandle.a("badgeId");
        this.i = e0.b(0, 1, null, 5);
        E.A(p0.j(this), new C4203d(this), null, new a(this, null), 2);
    }

    public final void A(d event) {
        Intrinsics.checkNotNullParameter(event, "event");
        if (Intrinsics.b(event, com.quizlet.features.achievements.data.b.a)) {
            this.i.h(com.quizlet.features.achievements.navigation.a.a);
            return;
        }
        if (!(event instanceof com.quizlet.features.achievements.data.a)) {
            if (!Intrinsics.b(event, com.quizlet.features.achievements.data.c.a)) {
                throw new NoWhenBranchMatchedException();
            }
            E.A(p0.j(this), new C4203d(this), null, new a(this, null), 2);
            return;
        }
        String badgeId = ((com.quizlet.features.achievements.data.a) event).a;
        AchievementsEventLogger achievementsEventLogger = (AchievementsEventLogger) this.e.get();
        achievementsEventLogger.getClass();
        Intrinsics.checkNotNullParameter(badgeId, "badgeId");
        AchievementsEventLog.Companion companion = AchievementsEventLog.b;
        androidx.navigation.internal.h hVar = new androidx.navigation.internal.h(badgeId, 14);
        companion.getClass();
        achievementsEventLogger.a(AchievementsEventLog.Companion.a("achievements_badge_clicked", hVar));
    }
}

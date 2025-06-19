package com.quizlet.features.achievements.notification;

import androidx.lifecycle.X;
import androidx.lifecycle.p0;
import androidx.lifecycle.w0;
import com.onetrust.otpublishers.headless.UI.fragment.q;
import com.quizlet.eventlogger.features.achievements.AchievementsToastInteractionEventLog;
import com.quizlet.eventlogger.features.achievements.AchievementsToastInteractionLogger;
import com.quizlet.generated.enums.EnumC4485h;
import java.util.concurrent.TimeUnit;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.E;

@Metadata
/* loaded from: classes2.dex */
public final class f extends w0 implements com.quizlet.features.achievements.achievement.d {
    public final q b;
    public final long c;
    public final AchievementsToastInteractionLogger d;
    public final com.quizlet.time.b e;
    public final X f;
    public final X g;
    public long h;

    public f(q achievementsNotificationUseCase, long j, AchievementsToastInteractionLogger eventsLogger) {
        com.quizlet.time.b timeProvider = com.quizlet.time.b.a;
        Intrinsics.checkNotNullParameter(achievementsNotificationUseCase, "achievementsNotificationUseCase");
        Intrinsics.checkNotNullParameter(eventsLogger, "eventsLogger");
        Intrinsics.checkNotNullParameter(timeProvider, "timeProvider");
        this.b = achievementsNotificationUseCase;
        this.c = j;
        this.d = eventsLogger;
        this.e = timeProvider;
        this.f = new X(1);
        this.g = new X(1);
    }

    public final void A() {
        E.A(p0.j(this), null, null, new e(this, null), 3);
    }

    public final void B(EnumC4485h notificationType) {
        Intrinsics.checkNotNullParameter(notificationType, "notificationType");
        long j = this.h;
        Intrinsics.checkNotNullParameter(notificationType, "notificationType");
        this.e.getClass();
        long jMin = Math.min(com.quizlet.time.b.a() - j, TimeUnit.MILLISECONDS.toSeconds(5000L));
        String notificationType2 = notificationType.a();
        AchievementsToastInteractionLogger achievementsToastInteractionLogger = this.d;
        achievementsToastInteractionLogger.getClass();
        Intrinsics.checkNotNullParameter(notificationType2, "notificationType");
        AchievementsToastInteractionEventLog.Companion companion = AchievementsToastInteractionEventLog.b;
        com.quizlet.eventlogger.features.achievements.a aVar = new com.quizlet.eventlogger.features.achievements.a(notificationType2, (int) jMin, 0);
        companion.getClass();
        achievementsToastInteractionLogger.a(AchievementsToastInteractionEventLog.Companion.a("achievements_toast_dismissed_swipe", aVar));
    }
}

package com.quizlet.features.achievements.achievement;

import com.quizlet.eventlogger.features.achievements.AchievementsToastInteractionEventLog;
import com.quizlet.eventlogger.features.achievements.AchievementsToastInteractionLogger;
import com.quizlet.generated.enums.EnumC4485h;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final /* synthetic */ class c implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ AchievementEarnedView b;

    public /* synthetic */ c(AchievementEarnedView achievementEarnedView, int i) {
        this.a = i;
        this.b = achievementEarnedView;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        AchievementEarnedView achievementEarnedView = this.b;
        switch (this.a) {
            case 0:
                int i = AchievementEarnedView.s;
                achievementEarnedView.h(e.c);
                return Unit.a;
            default:
                int i2 = AchievementEarnedView.s;
                achievementEarnedView.getClass();
                achievementEarnedView.h(e.b);
                d dVar = achievementEarnedView.o;
                if (dVar != null) {
                    EnumC4485h notificationType = achievementEarnedView.p;
                    if (notificationType == null) {
                        Intrinsics.m("notificationType");
                        throw null;
                    }
                    com.quizlet.features.achievements.notification.f fVar = (com.quizlet.features.achievements.notification.f) dVar;
                    Intrinsics.checkNotNullParameter(notificationType, "notificationType");
                    fVar.g.j(Long.valueOf(fVar.c));
                    String notificationType2 = notificationType.a();
                    AchievementsToastInteractionLogger achievementsToastInteractionLogger = fVar.d;
                    achievementsToastInteractionLogger.getClass();
                    Intrinsics.checkNotNullParameter(notificationType2, "notificationType");
                    AchievementsToastInteractionEventLog.Companion companion = AchievementsToastInteractionEventLog.b;
                    androidx.navigation.internal.h hVar = new androidx.navigation.internal.h(notificationType2, 15);
                    companion.getClass();
                    achievementsToastInteractionLogger.a(AchievementsToastInteractionEventLog.Companion.a("achievements_toast_tapped", hVar));
                }
                return Unit.a;
        }
    }
}

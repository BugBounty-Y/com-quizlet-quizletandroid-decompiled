package com.quizlet.features.achievements.home;

import androidx.lifecycle.w0;
import com.quizlet.eventlogger.features.achievements.AchievementsEventLogger;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes2.dex */
public final class a extends w0 {
    public final AchievementsEventLogger b;

    public a(AchievementsEventLogger achievementsEventLogger) {
        Intrinsics.checkNotNullParameter(achievementsEventLogger, "achievementsEventLogger");
        this.b = achievementsEventLogger;
    }
}

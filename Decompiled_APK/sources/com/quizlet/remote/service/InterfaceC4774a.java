package com.quizlet.remote.service;

import com.quizlet.remote.model.achievements.AchievementsEvent;
import com.quizlet.remote.model.achievements.BadgeResponse;
import com.quizlet.remote.model.achievements.BadgesResponse;
import com.quizlet.remote.model.achievements.RelevantNotificationResponse;
import com.quizlet.remote.model.achievements.StreakResponse;
import com.quizlet.remote.model.achievements.StreaksHistoryResponse;
import kotlin.Metadata;
import org.jetbrains.annotations.NotNull;

@Metadata
/* renamed from: com.quizlet.remote.service.a, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public interface InterfaceC4774a {
    @retrofit2.http.o("achievements/eventAsync")
    @NotNull
    io.reactivex.rxjava3.core.a a(@NotNull @retrofit2.http.a AchievementsEvent achievementsEvent);

    @retrofit2.http.f("achievements/notifications/relevant")
    @NotNull
    io.reactivex.rxjava3.core.p<RelevantNotificationResponse> b();

    @retrofit2.http.f("achievements/streak")
    @NotNull
    io.reactivex.rxjava3.core.p<StreakResponse> c(@retrofit2.http.t("getNewStreak") boolean z);

    @retrofit2.http.f("achievements/history/{year}/{month}")
    @NotNull
    io.reactivex.rxjava3.core.p<StreaksHistoryResponse> d(@retrofit2.http.s("year") int i, @retrofit2.http.s("month") int i2);

    @retrofit2.http.f("achievements/badges")
    @NotNull
    io.reactivex.rxjava3.core.p<BadgesResponse> e();

    @retrofit2.http.p("achievements/notifications/shown")
    @NotNull
    io.reactivex.rxjava3.core.a f();

    @retrofit2.http.f("achievements/badges/last")
    @NotNull
    io.reactivex.rxjava3.core.p<BadgeResponse> g();
}

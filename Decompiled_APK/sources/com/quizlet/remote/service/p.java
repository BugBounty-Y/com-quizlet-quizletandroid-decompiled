package com.quizlet.remote.service;

import com.quizlet.remote.model.base.ApiThreeWrapper;
import com.quizlet.remote.model.metering.MeteringInfoResponse;
import kotlin.Metadata;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public interface p {
    @retrofit2.http.f("metering/event")
    @NotNull
    io.reactivex.rxjava3.core.p<ApiThreeWrapper<MeteringInfoResponse>> a(@retrofit2.http.t("eventType") int i, @retrofit2.http.t("resourceId") Long l);

    @retrofit2.http.o("metering/event")
    @NotNull
    io.reactivex.rxjava3.core.p<ApiThreeWrapper<MeteringInfoResponse>> b(@retrofit2.http.t("eventType") int i, @retrofit2.http.t("resourceId") Long l, @retrofit2.http.t("eventCount") Integer num);
}

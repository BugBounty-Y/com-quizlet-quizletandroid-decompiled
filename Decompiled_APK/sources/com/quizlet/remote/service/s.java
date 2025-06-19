package com.quizlet.remote.service;

import com.quizlet.remote.model.base.ApiPostBody;
import com.quizlet.remote.model.base.ApiThreeWrapper;
import com.quizlet.remote.model.progress.ProgressResetResponse;
import com.quizlet.remote.model.progress.RemoteProgressReset;
import kotlin.Metadata;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public interface s {
    @retrofit2.http.f("progress-resets-v2")
    @NotNull
    io.reactivex.rxjava3.core.p<ApiThreeWrapper<ProgressResetResponse>> a(@retrofit2.http.t("filters[personId]") long j, @retrofit2.http.t("filters[containerId]") long j2, @retrofit2.http.t("filters[containerType]") int i);

    @retrofit2.http.o("progress-resets-v2/save")
    @NotNull
    io.reactivex.rxjava3.core.p<ApiThreeWrapper<ProgressResetResponse>> b(@NotNull @retrofit2.http.a ApiPostBody<RemoteProgressReset> apiPostBody);
}

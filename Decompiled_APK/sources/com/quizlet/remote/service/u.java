package com.quizlet.remote.service;

import com.quizlet.remote.model.base.ApiThreeWrapper;
import com.quizlet.remote.model.set.RecommendedSetsAgeLocationBasedResponse;
import kotlin.Metadata;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public interface u {
    @retrofit2.http.f("sets/age-location-recommendations")
    Object a(@NotNull kotlin.coroutines.h<? super ApiThreeWrapper<RecommendedSetsAgeLocationBasedResponse>> hVar);
}

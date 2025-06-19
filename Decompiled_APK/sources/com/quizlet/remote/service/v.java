package com.quizlet.remote.service;

import com.quizlet.remote.model.base.ApiPostBody;
import com.quizlet.remote.model.base.ApiThreeWrapper;
import com.quizlet.remote.model.set.IrrelevantRecommendationsResponse;
import com.quizlet.remote.model.set.IrrelevantStudySetPostBody;
import com.quizlet.remote.model.set.RecommendedSetsBehaviorBasedResponse;
import com.quizlet.remote.model.set.RecommendedSetsSchoolCourseBasedResponse;
import kotlin.Metadata;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public interface v {
    @retrofit2.http.o("irrelevant-recommendations")
    @NotNull
    io.reactivex.rxjava3.core.p<ApiThreeWrapper<IrrelevantRecommendationsResponse>> a(@NotNull @retrofit2.http.a ApiPostBody<IrrelevantStudySetPostBody> apiPostBody);

    @retrofit2.http.f("sets/person-recommendations")
    @NotNull
    io.reactivex.rxjava3.core.p<ApiThreeWrapper<RecommendedSetsBehaviorBasedResponse>> b(@retrofit2.http.t("algo") int i, @retrofit2.http.t("filters[sets][purchasableType]") int i2);

    @retrofit2.http.f("sets/edgy-recommendations")
    @NotNull
    io.reactivex.rxjava3.core.p<ApiThreeWrapper<RecommendedSetsSchoolCourseBasedResponse>> c(@retrofit2.http.t("algo") int i, @retrofit2.http.t("filters[sets][purchasableType]") int i2);
}

package com.quizlet.remote.service;

import com.quizlet.remote.model.base.ApiThreeWrapper;
import com.quizlet.remote.model.explanations.search.SearchTypeAheadResultResponse;
import com.quizlet.remote.model.search.SearchAllResultsResponse;
import com.quizlet.remote.model.search.SearchBannerResponseWrapper;
import com.quizlet.remote.model.search.SearchMisspellingsResponse;
import kotlin.Metadata;
import org.jetbrains.annotations.NotNull;
import retrofit2.K;

@Metadata
/* loaded from: classes3.dex */
public interface y {
    @retrofit2.http.f("suggestions/query")
    Object a(@retrofit2.http.t("query") @NotNull String str, @NotNull kotlin.coroutines.h<? super K<ApiThreeWrapper<SearchTypeAheadResultResponse>>> hVar);

    @retrofit2.http.f("blended/search?include[set]=creator&include[class]=school&include[term]=set")
    Object b(@retrofit2.http.t("query") @NotNull String str, @retrofit2.http.t("includeTermSearch") int i, @retrofit2.http.t("includeShelfRanking") int i2, @retrofit2.http.t("showSocialProof") int i3, @retrofit2.http.t("isQueryCorrected") boolean z, @NotNull kotlin.coroutines.h<? super K<ApiThreeWrapper<SearchAllResultsResponse>>> hVar);

    @retrofit2.http.f("misspellings/search")
    Object c(@retrofit2.http.t("query") @NotNull String str, @NotNull kotlin.coroutines.h<? super K<SearchMisspellingsResponse>> hVar);

    @retrofit2.http.f("query-lookup/banner-metadata")
    Object d(@retrofit2.http.t("query") @NotNull String str, @NotNull kotlin.coroutines.h<? super K<ApiThreeWrapper<SearchBannerResponseWrapper>>> hVar);
}

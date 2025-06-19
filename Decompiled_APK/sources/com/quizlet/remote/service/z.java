package com.quizlet.remote.service;

import com.quizlet.remote.model.base.ApiPostBody;
import com.quizlet.remote.model.base.ApiThreeWrapper;
import com.quizlet.remote.model.selectedterm.SelectedTermRequest;
import com.quizlet.remote.model.selectedterm.SelectedTermResponse;
import java.util.Map;
import kotlin.Metadata;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public interface z {
    @retrofit2.http.o("selected-terms/save")
    Object a(@NotNull @retrofit2.http.a ApiPostBody<SelectedTermRequest> apiPostBody, @NotNull kotlin.coroutines.h<? super ApiThreeWrapper<SelectedTermResponse>> hVar);

    @retrofit2.http.f("selected-terms")
    Object b(@retrofit2.http.t("filters[setId]") long j, @retrofit2.http.t("filters[personId]") long j2, @NotNull @retrofit2.http.u Map<String, String> map, @NotNull kotlin.coroutines.h<? super ApiThreeWrapper<SelectedTermResponse>> hVar);

    @retrofit2.http.h(hasBody = true, method = "DELETE", path = "selected-terms")
    Object c(@NotNull @retrofit2.http.a ApiPostBody<SelectedTermRequest> apiPostBody, @NotNull kotlin.coroutines.h<? super ApiThreeWrapper<SelectedTermResponse>> hVar);
}

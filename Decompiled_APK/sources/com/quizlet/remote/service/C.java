package com.quizlet.remote.service;

import com.quizlet.remote.model.base.ApiThreeWrapper;
import com.quizlet.remote.model.term.TermResponse;
import java.util.Map;
import kotlin.Metadata;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public interface C {
    @retrofit2.http.f("terms")
    Object a(@retrofit2.http.t("filters[setId]") long j, @retrofit2.http.t("filters[isDeleted]") Boolean bool, @NotNull @retrofit2.http.u Map<String, String> map, @NotNull kotlin.coroutines.h<? super ApiThreeWrapper<TermResponse>> hVar);
}

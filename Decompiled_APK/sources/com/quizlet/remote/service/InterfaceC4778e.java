package com.quizlet.remote.service;

import com.quizlet.remote.model.base.ApiThreeWrapper;
import com.quizlet.remote.model.qclass.ClassResponse;
import kotlin.Metadata;
import org.jetbrains.annotations.NotNull;
import retrofit2.K;

@Metadata
/* renamed from: com.quizlet.remote.service.e, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public interface InterfaceC4778e {
    @retrofit2.http.f("classes/search?include[class][]=school")
    @NotNull
    io.reactivex.rxjava3.core.p<K<ApiThreeWrapper<ClassResponse>>> a(@retrofit2.http.t("query") @NotNull String str, @retrofit2.http.t("pagingToken") String str2, @retrofit2.http.t("page") Integer num, @retrofit2.http.t("perPage") int i);
}

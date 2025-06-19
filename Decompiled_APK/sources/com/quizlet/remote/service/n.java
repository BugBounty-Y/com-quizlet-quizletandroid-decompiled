package com.quizlet.remote.service;

import com.quizlet.remote.model.base.ApiPostBody;
import com.quizlet.remote.model.base.ApiThreeWrapper;
import com.quizlet.remote.model.folderset.FolderSetResponse;
import com.quizlet.remote.model.folderset.RemoteFolderSet;
import kotlin.Metadata;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public interface n {
    @retrofit2.http.h(hasBody = true, method = "DELETE", path = "folder-sets")
    @NotNull
    io.reactivex.rxjava3.core.p<ApiThreeWrapper<FolderSetResponse>> a(@NotNull @retrofit2.http.a ApiPostBody<RemoteFolderSet> apiPostBody);

    @retrofit2.http.o("folder-sets/save")
    @NotNull
    io.reactivex.rxjava3.core.p<ApiThreeWrapper<FolderSetResponse>> b(@NotNull @retrofit2.http.a ApiPostBody<RemoteFolderSet> apiPostBody);

    @retrofit2.http.f("folder-sets")
    @NotNull
    io.reactivex.rxjava3.core.p<ApiThreeWrapper<FolderSetResponse>> c(@retrofit2.http.t("filters[folderId]") String str, @retrofit2.http.t("filters[setId]") String str2);
}

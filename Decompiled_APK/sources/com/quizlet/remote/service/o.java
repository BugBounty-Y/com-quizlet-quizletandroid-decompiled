package com.quizlet.remote.service;

import com.quizlet.remote.model.base.ApiPostBody;
import com.quizlet.remote.model.base.ApiThreeWrapper;
import com.quizlet.remote.model.folderstudymaterial.FolderStudyMaterialResponse;
import com.quizlet.remote.model.folderstudymaterial.FolderStudyMaterialsRequest;
import com.quizlet.remote.model.foldertoadd.FolderToAddMaterialResponse;
import java.util.List;
import java.util.Map;
import kotlin.Metadata;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public interface o {
    @retrofit2.http.f("folder-study-materials/folders-to-add")
    Object a(@retrofit2.http.t("studyMaterialId") @NotNull String str, @retrofit2.http.t("studyMaterialType") int i, @retrofit2.http.t("filters[folderId]") Long l, @NotNull kotlin.coroutines.h<? super ApiThreeWrapper<FolderToAddMaterialResponse>> hVar);

    @retrofit2.http.o("folder-study-materials/save")
    Object b(@NotNull @retrofit2.http.a ApiPostBody<FolderStudyMaterialsRequest> apiPostBody, @NotNull kotlin.coroutines.h<? super ApiThreeWrapper<FolderStudyMaterialResponse>> hVar);

    @retrofit2.http.f("folder-study-materials")
    Object c(@retrofit2.http.t("filters[studyMaterialType]") int i, @retrofit2.http.t("filters[studyMaterialId]") @NotNull String str, @retrofit2.http.t("filters[userId]") Long l, @NotNull @retrofit2.http.u Map<String, String> map, @NotNull kotlin.coroutines.h<? super ApiThreeWrapper<FolderStudyMaterialResponse>> hVar);

    @retrofit2.http.h(hasBody = true, method = "DELETE", path = "folder-study-materials")
    Object d(@NotNull @retrofit2.http.a ApiPostBody<FolderStudyMaterialsRequest> apiPostBody, @NotNull kotlin.coroutines.h<? super ApiThreeWrapper<FolderStudyMaterialResponse>> hVar);

    @retrofit2.http.f("folder-study-materials")
    Object e(@retrofit2.http.t("filters[folderId]") long j, @retrofit2.http.t("filters[studyMaterialType][]") @NotNull List<Integer> list, @NotNull @retrofit2.http.u Map<String, String> map, @NotNull kotlin.coroutines.h<? super ApiThreeWrapper<FolderStudyMaterialResponse>> hVar);
}

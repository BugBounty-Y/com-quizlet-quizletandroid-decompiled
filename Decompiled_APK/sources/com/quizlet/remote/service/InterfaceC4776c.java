package com.quizlet.remote.service;

import com.quizlet.remote.model.base.ApiPostBody;
import com.quizlet.remote.model.base.ApiThreeWrapper;
import com.quizlet.remote.model.classfolder.ClassFolderResponse;
import com.quizlet.remote.model.classfolder.RemoteClassFolder;
import com.quizlet.remote.model.union.folderwithcreatorinclass.FolderWithCreatorInClassResponse;
import kotlin.Metadata;
import org.jetbrains.annotations.NotNull;

@Metadata
/* renamed from: com.quizlet.remote.service.c, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public interface InterfaceC4776c {
    @retrofit2.http.f("class-folders")
    @NotNull
    io.reactivex.rxjava3.core.p<ApiThreeWrapper<ClassFolderResponse>> a(@retrofit2.http.t("filters[classId]") String str, @retrofit2.http.t("filters[folderId]") String str2);

    @retrofit2.http.h(hasBody = true, method = "DELETE", path = "class-folders")
    @NotNull
    io.reactivex.rxjava3.core.p<ApiThreeWrapper<ClassFolderResponse>> b(@NotNull @retrofit2.http.a ApiPostBody<RemoteClassFolder> apiPostBody);

    @retrofit2.http.f("class-folders?include[classFolder][folder][]=user")
    @NotNull
    io.reactivex.rxjava3.core.p<ApiThreeWrapper<FolderWithCreatorInClassResponse>> c(@retrofit2.http.t("filters[classId]") @NotNull String str);

    @retrofit2.http.o("class-folders/save")
    @NotNull
    io.reactivex.rxjava3.core.p<ApiThreeWrapper<ClassFolderResponse>> d(@NotNull @retrofit2.http.a ApiPostBody<RemoteClassFolder> apiPostBody);
}

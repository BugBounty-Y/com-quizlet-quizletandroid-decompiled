package com.quizlet.remote.service;

import com.quizlet.remote.model.base.ApiThreeWrapper;
import com.quizlet.remote.model.union.studysetwithcreatorinclass.StudySetWithCreatorInClassResponse;
import kotlin.Metadata;
import org.jetbrains.annotations.NotNull;

@Metadata
/* renamed from: com.quizlet.remote.service.f, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public interface InterfaceC4779f {
    @retrofit2.http.f("class-sets?include[classSet][set][]=creator&filters[folderId]=")
    Object a(@retrofit2.http.t("filters[classId]") @NotNull String str, @retrofit2.http.t("page") int i, @retrofit2.http.t("pagingToken") String str2, @NotNull kotlin.coroutines.h<? super ApiThreeWrapper<StudySetWithCreatorInClassResponse>> hVar);

    @retrofit2.http.f("class-sets?include[classSet][set][]=creator")
    Object b(@retrofit2.http.t("filters[setId]") @NotNull String str, @retrofit2.http.t("page") int i, @retrofit2.http.t("pagingToken") String str2, @NotNull kotlin.coroutines.h<? super ApiThreeWrapper<StudySetWithCreatorInClassResponse>> hVar);

    @retrofit2.http.f("class-sets?include[classSet][set][]=creator")
    Object c(@retrofit2.http.t("filters[classId]") @NotNull String str, @retrofit2.http.t("page") int i, @retrofit2.http.t("pagingToken") String str2, @NotNull kotlin.coroutines.h<? super ApiThreeWrapper<StudySetWithCreatorInClassResponse>> hVar);
}

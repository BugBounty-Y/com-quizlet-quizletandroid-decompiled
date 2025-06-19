package com.quizlet.remote.service;

import com.quizlet.remote.model.base.ApiThreeWrapper;
import com.quizlet.remote.model.folder.FolderResponse;
import com.quizlet.remote.model.folder.course.SaveCourseToFolderRequestBody;
import kotlin.Metadata;
import org.jetbrains.annotations.NotNull;

@Metadata
/* renamed from: com.quizlet.remote.service.g, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public interface InterfaceC4780g {
    @retrofit2.http.o("folders/{folderId}/add-school-course")
    Object a(@retrofit2.http.s("folderId") long j, @NotNull @retrofit2.http.a SaveCourseToFolderRequestBody saveCourseToFolderRequestBody, @NotNull kotlin.coroutines.h<? super ApiThreeWrapper<FolderResponse>> hVar);

    @retrofit2.http.o("folders/{folderId}/remove-school-course")
    Object b(@retrofit2.http.s("folderId") long j, @NotNull kotlin.coroutines.h<? super ApiThreeWrapper<FolderResponse>> hVar);
}

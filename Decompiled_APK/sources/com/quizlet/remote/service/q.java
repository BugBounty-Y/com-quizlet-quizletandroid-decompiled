package com.quizlet.remote.service;

import com.quizlet.remote.model.base.ApiThreeWrapper;
import com.quizlet.remote.model.notes.RemoteNotesResponse;
import com.quizlet.remote.model.notes.RemoteStudyNotesArtifactsResponse;
import com.quizlet.remote.model.notes.StudyNotesArtifactRequest;
import com.quizlet.remote.model.notes.StudyNotesRequest;
import kotlin.Metadata;
import org.jetbrains.annotations.NotNull;
import retrofit2.K;

@Metadata
/* loaded from: classes3.dex */
public interface q {
    @retrofit2.http.p("study-notes/{uuid}")
    Object a(@retrofit2.http.s("uuid") @NotNull String str, @NotNull @retrofit2.http.a StudyNotesRequest studyNotesRequest, @NotNull kotlin.coroutines.h<? super ApiThreeWrapper<RemoteNotesResponse>> hVar);

    @retrofit2.http.f("study-notes/recents")
    Object b(@retrofit2.http.t("limit") int i, @NotNull kotlin.coroutines.h<? super ApiThreeWrapper<RemoteNotesResponse>> hVar);

    @retrofit2.http.p("artifacts/{uuid}")
    Object c(@retrofit2.http.s("uuid") @NotNull String str, @NotNull @retrofit2.http.a StudyNotesArtifactRequest studyNotesArtifactRequest, @NotNull kotlin.coroutines.h<? super ApiThreeWrapper<RemoteStudyNotesArtifactsResponse>> hVar);

    @retrofit2.http.b("study-notes/{uuid}")
    Object d(@retrofit2.http.s("uuid") @NotNull String str, @NotNull kotlin.coroutines.h<? super K<RemoteNotesResponse>> hVar);
}

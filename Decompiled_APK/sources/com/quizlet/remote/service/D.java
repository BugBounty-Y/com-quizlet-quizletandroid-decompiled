package com.quizlet.remote.service;

import com.quizlet.remote.model.base.ApiThreeWrapper;
import com.quizlet.remote.model.universaluploadflow.RemoteUniversalUploadFlowFlashcardSetsResponse;
import com.quizlet.remote.model.universaluploadflow.UniversalUploadFlowPracticeTestsResponse;
import com.quizlet.remote.model.universaluploadflow.UniversalUploadFlowPracticeTestsStatusResponse;
import com.quizlet.remote.model.universaluploadflow.UploadFlashcardSetPracticeTestsBody;
import com.quizlet.remote.model.universaluploadflow.UploadTextPracticeTestsBody;
import java.util.Map;
import kotlin.Metadata;
import org.jetbrains.annotations.NotNull;
import retrofit2.K;

@Metadata
/* loaded from: classes3.dex */
public interface D {
    @retrofit2.http.o("practice-tests/document-uploads/flashcard-set")
    Object a(@NotNull @retrofit2.http.a UploadFlashcardSetPracticeTestsBody uploadFlashcardSetPracticeTestsBody, @retrofit2.http.t("requestId") @NotNull String str, @NotNull kotlin.coroutines.h<? super K<ApiThreeWrapper<UniversalUploadFlowPracticeTestsResponse>>> hVar);

    @retrofit2.http.o("practice-tests/document-uploads/plaintext")
    Object b(@NotNull @retrofit2.http.a UploadTextPracticeTestsBody uploadTextPracticeTestsBody, @retrofit2.http.t("requestId") @NotNull String str, @NotNull kotlin.coroutines.h<? super K<ApiThreeWrapper<UniversalUploadFlowPracticeTestsResponse>>> hVar);

    @retrofit2.http.f("practice-tests/question-banks/{questionBankUuid}/status")
    Object c(@retrofit2.http.s("questionBankUuid") @NotNull String str, @retrofit2.http.t("requestId") @NotNull String str2, @NotNull kotlin.coroutines.h<? super ApiThreeWrapper<UniversalUploadFlowPracticeTestsStatusResponse>> hVar);

    @retrofit2.http.o("practice-tests/document-uploads/file")
    Object d(@NotNull @retrofit2.http.a okhttp3.F f, @retrofit2.http.t("requestId") @NotNull String str, @retrofit2.http.t("inputType") @NotNull String str2, @retrofit2.http.t("questionCompatibility") @NotNull String str3, @NotNull kotlin.coroutines.h<? super K<ApiThreeWrapper<UniversalUploadFlowPracticeTestsResponse>>> hVar);

    @retrofit2.http.f("feed")
    Object e(@NotNull @retrofit2.http.u Map<String, Boolean> map, @NotNull @retrofit2.http.u Map<String, String> map2, @retrofit2.http.t("query") String str, @retrofit2.http.t("perPage") Integer num, @retrofit2.http.t("seenClassSetIds") String str2, @retrofit2.http.t("seenCreatedSetIds") String str3, @retrofit2.http.t("seenSessionIds") String str4, @NotNull kotlin.coroutines.h<? super ApiThreeWrapper<RemoteUniversalUploadFlowFlashcardSetsResponse>> hVar);
}

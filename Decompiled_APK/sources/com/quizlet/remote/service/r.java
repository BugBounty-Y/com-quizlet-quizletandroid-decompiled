package com.quizlet.remote.service;

import com.quizlet.remote.model.base.ApiThreeWrapper;
import com.quizlet.remote.model.practicetests.CopyPracticeTestBody;
import com.quizlet.remote.model.practicetests.GradePracticeTestBody;
import com.quizlet.remote.model.practicetests.PracticeTestBody;
import com.quizlet.remote.model.practicetests.RemoteCopyPracticeTestResponse;
import com.quizlet.remote.model.practicetests.RemoteCreatedPracticeTestResponse;
import com.quizlet.remote.model.practicetests.RemotePracticeTestResponse;
import com.quizlet.remote.model.practicetests.RemotePracticeTestResultResponse;
import com.quizlet.remote.model.practicetests.RemoteQuestionBankPreviewResponse;
import com.quizlet.remote.model.practicetests.RemoteQuestionBankResultsResponse;
import com.quizlet.remote.model.practicetests.RemoteQuestionBanksResponse;
import com.quizlet.remote.model.practicetests.RemoteUpdateGradedAnswerResponse;
import com.quizlet.remote.model.practicetests.RemoteUpdateQuestionBankResponse;
import com.quizlet.remote.model.practicetests.UpdateGradedAnswerBody;
import com.quizlet.remote.model.practicetests.UpdateQuestionBankBody;
import kotlin.Metadata;
import org.jetbrains.annotations.NotNull;
import retrofit2.K;

@Metadata
/* loaded from: classes3.dex */
public interface r {
    @retrofit2.http.f("practice-tests/{practiceTestId}")
    Object a(@retrofit2.http.s("practiceTestId") @NotNull String str, @retrofit2.http.t("requestId") @NotNull String str2, @retrofit2.http.t("questionCompatibility") @NotNull String str3, @NotNull kotlin.coroutines.h<? super ApiThreeWrapper<RemotePracticeTestResponse>> hVar);

    @retrofit2.http.f("practice-tests/question-banks/{uuid}/preview")
    Object b(@retrofit2.http.s("uuid") @NotNull String str, @retrofit2.http.t("requestId") @NotNull String str2, @retrofit2.http.t("questionCompatibility") @NotNull String str3, @NotNull kotlin.coroutines.h<? super ApiThreeWrapper<RemoteQuestionBankPreviewResponse>> hVar);

    @retrofit2.http.f("practice-tests/question-banks")
    Object c(@retrofit2.http.t("requestId") @NotNull String str, @retrofit2.http.t("ownerId") long j, @NotNull kotlin.coroutines.h<? super ApiThreeWrapper<RemoteQuestionBanksResponse>> hVar);

    @retrofit2.http.o("practice-tests/{practiceTestId}/grade")
    Object d(@NotNull @retrofit2.http.a GradePracticeTestBody gradePracticeTestBody, @retrofit2.http.s("practiceTestId") @NotNull String str, @retrofit2.http.t("requestId") @NotNull String str2, @NotNull kotlin.coroutines.h<? super K<ApiThreeWrapper<RemoteCreatedPracticeTestResponse>>> hVar);

    @retrofit2.http.o("practice-tests")
    Object e(@NotNull @retrofit2.http.a PracticeTestBody practiceTestBody, @retrofit2.http.t("requestId") @NotNull String str, @NotNull kotlin.coroutines.h<? super K<ApiThreeWrapper<RemoteCreatedPracticeTestResponse>>> hVar);

    @retrofit2.http.f("practice-tests/{uuid}/results")
    Object f(@retrofit2.http.s("uuid") @NotNull String str, @retrofit2.http.t("requestId") @NotNull String str2, @retrofit2.http.t("questionCompatibility") @NotNull String str3, @NotNull kotlin.coroutines.h<? super ApiThreeWrapper<RemotePracticeTestResultResponse>> hVar);

    @retrofit2.http.p("practice-tests/{practiceTestId}/answers/{questionId}")
    Object g(@NotNull @retrofit2.http.a UpdateGradedAnswerBody updateGradedAnswerBody, @retrofit2.http.s("practiceTestId") @NotNull String str, @retrofit2.http.s("questionId") @NotNull String str2, @retrofit2.http.t("requestId") @NotNull String str3, @NotNull kotlin.coroutines.h<? super ApiThreeWrapper<RemoteUpdateGradedAnswerResponse>> hVar);

    @retrofit2.http.o("practice-tests/{uuid}/copy")
    Object h(@NotNull @retrofit2.http.a CopyPracticeTestBody copyPracticeTestBody, @retrofit2.http.s("uuid") @NotNull String str, @retrofit2.http.t("requestId") @NotNull String str2, @NotNull kotlin.coroutines.h<? super ApiThreeWrapper<RemoteCopyPracticeTestResponse>> hVar);

    @retrofit2.http.p("practice-tests/question-banks/{uuid}")
    Object i(@NotNull @retrofit2.http.a UpdateQuestionBankBody updateQuestionBankBody, @retrofit2.http.s("uuid") @NotNull String str, @retrofit2.http.t("requestId") @NotNull String str2, @NotNull kotlin.coroutines.h<? super ApiThreeWrapper<RemoteUpdateQuestionBankResponse>> hVar);

    @retrofit2.http.f("practice-tests/results")
    Object j(@retrofit2.http.t("requestId") @NotNull String str, @retrofit2.http.t("questionBankUuid") @NotNull String str2, @NotNull kotlin.coroutines.h<? super ApiThreeWrapper<RemoteQuestionBankResultsResponse>> hVar);
}

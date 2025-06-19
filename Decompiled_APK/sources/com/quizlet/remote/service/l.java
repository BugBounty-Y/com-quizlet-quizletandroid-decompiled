package com.quizlet.remote.service;

import com.quizlet.remote.model.base.ApiPostBodySingle;
import com.quizlet.remote.model.base.ApiThreeWrapper;
import com.quizlet.remote.model.explanations.exercise.ExerciseDetailsResponse;
import com.quizlet.remote.model.explanations.feedback.RemoteExplanationsFeedback;
import com.quizlet.remote.model.explanations.myexplanations.RecentExplanationsResponse;
import com.quizlet.remote.model.explanations.myexplanations.RemoteMyExplanationsSession;
import com.quizlet.remote.model.explanations.question.QuestionResponse;
import com.quizlet.remote.model.explanations.search.ExplanationsSearchResultResponse;
import com.quizlet.remote.model.explanations.textbook.TextbookResponse;
import java.util.List;
import kotlin.Metadata;
import org.jetbrains.annotations.NotNull;
import retrofit2.K;

@Metadata
/* loaded from: classes3.dex */
public interface l {
    @retrofit2.http.f("explanations/search")
    @NotNull
    io.reactivex.rxjava3.core.p<K<ApiThreeWrapper<ExplanationsSearchResultResponse>>> a(@retrofit2.http.t("query") @NotNull String str, @retrofit2.http.t("page") Integer num, @retrofit2.http.t("pagingToken") String str2, @retrofit2.http.t("perPage") Integer num2, @retrofit2.http.t("filters") @NotNull List<String> list, @retrofit2.http.t("premiumOnly") boolean z);

    @retrofit2.http.f("explanations/recommendations/question/{id}/textbook")
    @NotNull
    io.reactivex.rxjava3.core.p<ApiThreeWrapper<TextbookResponse>> b(@retrofit2.http.s("id") @NotNull String str);

    @retrofit2.http.o("explanations/feedback")
    @NotNull
    io.reactivex.rxjava3.core.a c(@NotNull @retrofit2.http.a RemoteExplanationsFeedback remoteExplanationsFeedback);

    @retrofit2.http.o("explanations/sessions/save")
    @NotNull
    io.reactivex.rxjava3.core.a d(@NotNull @retrofit2.http.a ApiPostBodySingle<RemoteMyExplanationsSession> apiPostBodySingle);

    @retrofit2.http.f("explanations/textbooks/{isbn}")
    @NotNull
    io.reactivex.rxjava3.core.p<ApiThreeWrapper<TextbookResponse>> e(@retrofit2.http.s("isbn") @NotNull String str, @retrofit2.http.t("includeTableOfContents") boolean z);

    @retrofit2.http.f("explanations/questions/{id}")
    @NotNull
    io.reactivex.rxjava3.core.p<ApiThreeWrapper<QuestionResponse>> f(@retrofit2.http.s("id") @NotNull String str);

    @retrofit2.http.f("explanations/textbook-exercises/{id}")
    @NotNull
    io.reactivex.rxjava3.core.p<ApiThreeWrapper<ExerciseDetailsResponse>> g(@retrofit2.http.s("id") @NotNull String str);

    @retrofit2.http.f("explanations/recents")
    @NotNull
    io.reactivex.rxjava3.core.p<ApiThreeWrapper<RecentExplanationsResponse>> h(@retrofit2.http.t("limit") Integer num, @retrofit2.http.t("filters") String str);
}

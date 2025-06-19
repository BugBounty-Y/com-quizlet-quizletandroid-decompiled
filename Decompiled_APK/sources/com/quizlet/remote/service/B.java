package com.quizlet.remote.service;

import com.quizlet.db.data.models.base.AssociationNames;
import com.quizlet.remote.model.base.ApiThreeWrapper;
import com.quizlet.remote.model.union.studysetwithcreator.StudySetsWithCreatorsAndClassificationsResponse;
import java.util.List;
import kotlin.Metadata;
import org.jetbrains.annotations.NotNull;
import retrofit2.K;

@Metadata
/* loaded from: classes3.dex */
public interface B {
    @retrofit2.http.f("sets/{setIds}")
    @NotNull
    io.reactivex.rxjava3.core.p<ApiThreeWrapper<StudySetsWithCreatorsAndClassificationsResponse>> a(@retrofit2.http.s("setIds") @NotNull String str, @retrofit2.http.t("include[set][]") @NotNull List<String> list);

    @retrofit2.http.f("sets/search?include[set][]=creator")
    @NotNull
    io.reactivex.rxjava3.core.p<K<ApiThreeWrapper<StudySetsWithCreatorsAndClassificationsResponse>>> b(@retrofit2.http.t("query") @NotNull String str, @retrofit2.http.t("pagingToken") String str2, @retrofit2.http.t("page") Integer num, @retrofit2.http.t("perPage") int i, @retrofit2.http.t("numTerms") @NotNull String str3, @retrofit2.http.t(AssociationNames.CREATOR) @NotNull String str4, @retrofit2.http.t("contentType") @NotNull String str5, @retrofit2.http.t("showSocialProof") int i2);
}

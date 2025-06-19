package com.quizlet.remote.service;

import com.quizlet.remote.model.base.ApiPostBody;
import com.quizlet.remote.model.base.ApiThreeWrapper;
import com.quizlet.remote.model.school.RemoteDeleteSchoolMembershipResponse;
import com.quizlet.remote.model.school.RemoteNewSchool;
import com.quizlet.remote.model.school.RemoteSchoolResponse;
import com.quizlet.remote.model.school.memberships.RemoteDeleteSchoolMembership;
import com.quizlet.remote.model.school.memberships.RemoteNewSchoolMembership;
import com.quizlet.remote.model.school.memberships.RemoteSchoolMembershipResponse;
import com.quizlet.remote.model.school.memberships.SchoolMembershipResponse;
import kotlin.Metadata;
import org.jetbrains.annotations.NotNull;
import retrofit2.K;

@Metadata
/* loaded from: classes3.dex */
public interface x {
    @retrofit2.http.f("schools/suggestions")
    Object a(@NotNull kotlin.coroutines.h<? super K<ApiThreeWrapper<RemoteSchoolResponse>>> hVar);

    @retrofit2.http.o("school-memberships/save")
    Object b(@NotNull @retrofit2.http.a ApiPostBody<RemoteNewSchoolMembership> apiPostBody, @NotNull kotlin.coroutines.h<? super ApiThreeWrapper<RemoteSchoolMembershipResponse>> hVar);

    @retrofit2.http.f("schools/search")
    Object c(@retrofit2.http.t("query") @NotNull String str, @retrofit2.http.t("perPage") int i, @NotNull kotlin.coroutines.h<? super K<ApiThreeWrapper<RemoteSchoolResponse>>> hVar);

    @retrofit2.http.h(hasBody = true, method = "DELETE", path = "school-memberships")
    Object d(@NotNull @retrofit2.http.a ApiPostBody<RemoteDeleteSchoolMembership> apiPostBody, @NotNull kotlin.coroutines.h<? super ApiThreeWrapper<RemoteDeleteSchoolMembershipResponse>> hVar);

    @retrofit2.http.o("schools/save")
    Object e(@NotNull @retrofit2.http.a ApiPostBody<RemoteNewSchool> apiPostBody, @NotNull kotlin.coroutines.h<? super ApiThreeWrapper<RemoteSchoolResponse>> hVar);

    @retrofit2.http.f("school-memberships")
    Object f(@NotNull kotlin.coroutines.h<? super ApiThreeWrapper<SchoolMembershipResponse>> hVar);
}

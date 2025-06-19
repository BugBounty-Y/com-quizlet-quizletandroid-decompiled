package com.quizlet.remote.service;

import com.quizlet.db.data.models.persisted.fields.DBGroupFields;
import com.quizlet.remote.model.base.ApiPostBody;
import com.quizlet.remote.model.base.ApiThreeWrapper;
import com.quizlet.remote.model.course.RemoteCourseResponse;
import com.quizlet.remote.model.course.RemoteDeleteCourseMembership;
import com.quizlet.remote.model.course.RemoteDeleteCourseMembershipResponse;
import com.quizlet.remote.model.course.RemoteNewCourse;
import com.quizlet.remote.model.course.RemoteNewCourseMembership;
import com.quizlet.remote.model.course.RemoteNewCourseMembershipResponse;
import kotlin.Metadata;
import org.jetbrains.annotations.NotNull;
import retrofit2.K;

@Metadata
/* loaded from: classes3.dex */
public interface i {
    @retrofit2.http.p("course-memberships/save")
    Object a(@NotNull @retrofit2.http.a ApiPostBody<RemoteNewCourseMembership> apiPostBody, @NotNull kotlin.coroutines.h<? super ApiThreeWrapper<RemoteNewCourseMembershipResponse>> hVar);

    @retrofit2.http.h(hasBody = true, method = "DELETE", path = "course-memberships")
    Object b(@NotNull @retrofit2.http.a ApiPostBody<RemoteDeleteCourseMembership> apiPostBody, @NotNull kotlin.coroutines.h<? super ApiThreeWrapper<RemoteDeleteCourseMembershipResponse>> hVar);

    @retrofit2.http.f("courses/suggestions")
    Object c(@retrofit2.http.t(DBGroupFields.Names.SCHOOL_ID) long j, @retrofit2.http.t("isFilterSearch") boolean z, @NotNull kotlin.coroutines.h<? super K<ApiThreeWrapper<RemoteCourseResponse>>> hVar);

    @retrofit2.http.f("courses/search")
    Object d(@retrofit2.http.t("query") @NotNull String str, @retrofit2.http.t("perPage") int i, @retrofit2.http.t("edgyDataSearch") int i2, @NotNull kotlin.coroutines.h<? super K<ApiThreeWrapper<RemoteCourseResponse>>> hVar);

    @retrofit2.http.o("courses/save")
    Object e(@NotNull @retrofit2.http.a ApiPostBody<RemoteNewCourse> apiPostBody, @NotNull kotlin.coroutines.h<? super ApiThreeWrapper<RemoteCourseResponse>> hVar);

    @retrofit2.http.f("courses")
    Object f(@retrofit2.http.t("filters[name]") @NotNull String str, @retrofit2.http.t("filters[code]") @NotNull String str2, @retrofit2.http.t("filters[isDeleted]") boolean z, @NotNull kotlin.coroutines.h<? super ApiThreeWrapper<RemoteCourseResponse>> hVar);
}

package com.quizlet.remote.service;

import com.quizlet.remote.model.course.memberships.CourseInstanceResponse;
import kotlin.Metadata;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public interface h {
    @retrofit2.http.f("course-instance")
    @NotNull
    io.reactivex.rxjava3.core.p<CourseInstanceResponse> a();
}

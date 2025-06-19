package com.quizlet.remote.model.course;

import com.quizlet.remote.model.base.ApiResponse;
import com.squareup.moshi.InterfaceC4853h;
import com.squareup.moshi.m;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class RemoteCourseResponse extends ApiResponse {
    public final CourseModelsResponse d;

    @m(generateAdapter = true)
    @Metadata
    public static final class CourseModelsResponse {
        public final List a;

        public CourseModelsResponse(@InterfaceC4853h(name = "course") @NotNull List<RemoteCourse> course) {
            Intrinsics.checkNotNullParameter(course, "course");
            this.a = course;
        }

        @NotNull
        public final CourseModelsResponse copy(@InterfaceC4853h(name = "course") @NotNull List<RemoteCourse> course) {
            Intrinsics.checkNotNullParameter(course, "course");
            return new CourseModelsResponse(course);
        }

        public final boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            return (obj instanceof CourseModelsResponse) && Intrinsics.b(this.a, ((CourseModelsResponse) obj).a);
        }

        public final int hashCode() {
            return this.a.hashCode();
        }

        public final String toString() {
            return android.support.v4.media.session.a.n(")", new StringBuilder("CourseModelsResponse(course="), this.a);
        }
    }

    public RemoteCourseResponse(@InterfaceC4853h(name = "models") @NotNull CourseModelsResponse models) {
        Intrinsics.checkNotNullParameter(models, "models");
        this.d = models;
    }

    @NotNull
    public final RemoteCourseResponse copy(@InterfaceC4853h(name = "models") @NotNull CourseModelsResponse models) {
        Intrinsics.checkNotNullParameter(models, "models");
        return new RemoteCourseResponse(models);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof RemoteCourseResponse) && Intrinsics.b(this.d, ((RemoteCourseResponse) obj).d);
    }

    public final int hashCode() {
        return this.d.a.hashCode();
    }

    public final String toString() {
        return "RemoteCourseResponse(models=" + this.d + ")";
    }
}

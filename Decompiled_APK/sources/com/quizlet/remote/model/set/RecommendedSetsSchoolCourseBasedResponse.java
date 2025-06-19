package com.quizlet.remote.model.set;

import androidx.compose.animation.d0;
import com.quizlet.remote.model.base.ApiResponse;
import com.quizlet.remote.model.course.RemoteCourse;
import com.quizlet.remote.model.school.RemoteSchool;
import com.squareup.moshi.m;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class RecommendedSetsSchoolCourseBasedResponse extends ApiResponse {
    public final RecommendedSetsSchoolCourseBasedModels d;
    public final RecommendedSetsSchoolCourseBasedSource e;

    @m(generateAdapter = true)
    @Metadata
    public static final class RecommendedSetsSchoolCourseBasedModels {
        public final List a;
        public final List b;
        public final List c;

        public RecommendedSetsSchoolCourseBasedModels(List recommendedStudiable, List user, List set) {
            Intrinsics.checkNotNullParameter(recommendedStudiable, "recommendedStudiable");
            Intrinsics.checkNotNullParameter(user, "user");
            Intrinsics.checkNotNullParameter(set, "set");
            this.a = recommendedStudiable;
            this.b = user;
            this.c = set;
        }

        public final boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (!(obj instanceof RecommendedSetsSchoolCourseBasedModels)) {
                return false;
            }
            RecommendedSetsSchoolCourseBasedModels recommendedSetsSchoolCourseBasedModels = (RecommendedSetsSchoolCourseBasedModels) obj;
            return Intrinsics.b(this.a, recommendedSetsSchoolCourseBasedModels.a) && Intrinsics.b(this.b, recommendedSetsSchoolCourseBasedModels.b) && Intrinsics.b(this.c, recommendedSetsSchoolCourseBasedModels.c);
        }

        public final int hashCode() {
            return this.c.hashCode() + d0.f(this.a.hashCode() * 31, 31, this.b);
        }

        public final String toString() {
            StringBuilder sb = new StringBuilder("RecommendedSetsSchoolCourseBasedModels(recommendedStudiable=");
            sb.append(this.a);
            sb.append(", user=");
            sb.append(this.b);
            sb.append(", set=");
            return android.support.v4.media.session.a.n(")", sb, this.c);
        }
    }

    @m(generateAdapter = true)
    @Metadata
    public static final class RecommendedSetsSchoolCourseBasedSource {
        public final RemoteSchool a;
        public final RemoteCourse b;

        public RecommendedSetsSchoolCourseBasedSource(RemoteSchool remoteSchool, RemoteCourse remoteCourse) {
            this.a = remoteSchool;
            this.b = remoteCourse;
        }

        public final boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (!(obj instanceof RecommendedSetsSchoolCourseBasedSource)) {
                return false;
            }
            RecommendedSetsSchoolCourseBasedSource recommendedSetsSchoolCourseBasedSource = (RecommendedSetsSchoolCourseBasedSource) obj;
            return Intrinsics.b(this.a, recommendedSetsSchoolCourseBasedSource.a) && Intrinsics.b(this.b, recommendedSetsSchoolCourseBasedSource.b);
        }

        public final int hashCode() {
            RemoteSchool remoteSchool = this.a;
            int iHashCode = (remoteSchool == null ? 0 : remoteSchool.hashCode()) * 31;
            RemoteCourse remoteCourse = this.b;
            return iHashCode + (remoteCourse != null ? remoteCourse.hashCode() : 0);
        }

        public final String toString() {
            return "RecommendedSetsSchoolCourseBasedSource(school=" + this.a + ", course=" + this.b + ")";
        }
    }

    public RecommendedSetsSchoolCourseBasedResponse(RecommendedSetsSchoolCourseBasedModels models, RecommendedSetsSchoolCourseBasedSource source) {
        Intrinsics.checkNotNullParameter(models, "models");
        Intrinsics.checkNotNullParameter(source, "source");
        this.d = models;
        this.e = source;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof RecommendedSetsSchoolCourseBasedResponse)) {
            return false;
        }
        RecommendedSetsSchoolCourseBasedResponse recommendedSetsSchoolCourseBasedResponse = (RecommendedSetsSchoolCourseBasedResponse) obj;
        return Intrinsics.b(this.d, recommendedSetsSchoolCourseBasedResponse.d) && Intrinsics.b(this.e, recommendedSetsSchoolCourseBasedResponse.e);
    }

    public final int hashCode() {
        return this.e.hashCode() + (this.d.hashCode() * 31);
    }

    public final String toString() {
        return "RecommendedSetsSchoolCourseBasedResponse(models=" + this.d + ", source=" + this.e + ")";
    }
}

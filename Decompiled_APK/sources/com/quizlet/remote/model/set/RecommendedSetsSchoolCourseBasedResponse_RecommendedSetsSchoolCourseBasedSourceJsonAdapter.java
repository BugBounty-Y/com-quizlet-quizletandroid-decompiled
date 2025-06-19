package com.quizlet.remote.model.set;

import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.remote.model.course.RemoteCourse;
import com.quizlet.remote.model.school.RemoteSchool;
import com.quizlet.remote.model.set.RecommendedSetsSchoolCourseBasedResponse;
import com.squareup.moshi.D;
import com.squareup.moshi.l;
import com.squareup.moshi.p;
import com.squareup.moshi.w;
import kotlin.Metadata;
import kotlin.collections.M;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class RecommendedSetsSchoolCourseBasedResponse_RecommendedSetsSchoolCourseBasedSourceJsonAdapter extends l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final l b;
    public final l c;

    public RecommendedSetsSchoolCourseBasedResponse_RecommendedSetsSchoolCourseBasedSourceJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("school", "course");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        M m = M.a;
        l lVarA = moshi.a(RemoteSchool.class, m, "school");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(RemoteCourse.class, m, "course");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        RemoteSchool remoteSchool = null;
        RemoteCourse remoteCourse = null;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 == -1) {
                reader.m0();
                reader.n0();
            } else if (iK0 == 0) {
                remoteSchool = (RemoteSchool) this.b.a(reader);
            } else if (iK0 == 1) {
                remoteCourse = (RemoteCourse) this.c.a(reader);
            }
        }
        reader.i();
        return new RecommendedSetsSchoolCourseBasedResponse.RecommendedSetsSchoolCourseBasedSource(remoteSchool, remoteCourse);
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        RecommendedSetsSchoolCourseBasedResponse.RecommendedSetsSchoolCourseBasedSource recommendedSetsSchoolCourseBasedSource = (RecommendedSetsSchoolCourseBasedResponse.RecommendedSetsSchoolCourseBasedSource) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (recommendedSetsSchoolCourseBasedSource == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("school");
        this.b.g(writer, recommendedSetsSchoolCourseBasedSource.a);
        writer.l("course");
        this.c.g(writer, recommendedSetsSchoolCourseBasedSource.b);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(101, "GeneratedJsonAdapter(RecommendedSetsSchoolCourseBasedResponse.RecommendedSetsSchoolCourseBasedSource)", "toString(...)");
    }
}

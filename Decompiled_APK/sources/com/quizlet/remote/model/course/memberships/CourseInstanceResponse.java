package com.quizlet.remote.model.course.memberships;

import android.support.v4.media.session.a;
import com.squareup.moshi.m;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class CourseInstanceResponse {
    public final List a;

    public CourseInstanceResponse(List courseInstances) {
        Intrinsics.checkNotNullParameter(courseInstances, "courseInstances");
        this.a = courseInstances;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof CourseInstanceResponse) && Intrinsics.b(this.a, ((CourseInstanceResponse) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return a.n(")", new StringBuilder("CourseInstanceResponse(courseInstances="), this.a);
    }
}

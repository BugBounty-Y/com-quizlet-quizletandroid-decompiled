package com.quizlet.remote.model.course.memberships;

import com.quizlet.remote.model.course.RemoteCourse;
import com.quizlet.remote.model.school.RemoteSchool;
import com.squareup.moshi.m;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class RemoteCourseInstance {
    public final RemoteSchool a;
    public final RemoteCourse b;

    public RemoteCourseInstance(RemoteSchool school, RemoteCourse course) {
        Intrinsics.checkNotNullParameter(school, "school");
        Intrinsics.checkNotNullParameter(course, "course");
        this.a = school;
        this.b = course;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof RemoteCourseInstance)) {
            return false;
        }
        RemoteCourseInstance remoteCourseInstance = (RemoteCourseInstance) obj;
        return Intrinsics.b(this.a, remoteCourseInstance.a) && Intrinsics.b(this.b, remoteCourseInstance.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "RemoteCourseInstance(school=" + this.a + ", course=" + this.b + ")";
    }
}

package com.quizlet.remote.model.course;

import com.squareup.moshi.InterfaceC4853h;
import com.squareup.moshi.m;
import kotlin.Metadata;
import org.jetbrains.annotations.NotNull;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class RemoteDeleteCourseMembership {
    public final long a;
    public final long b;

    public RemoteDeleteCourseMembership(@InterfaceC4853h(name = "courseId") long j, @InterfaceC4853h(name = "userId") long j2) {
        this.a = j;
        this.b = j2;
    }

    @NotNull
    public final RemoteDeleteCourseMembership copy(@InterfaceC4853h(name = "courseId") long j, @InterfaceC4853h(name = "userId") long j2) {
        return new RemoteDeleteCourseMembership(j, j2);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof RemoteDeleteCourseMembership)) {
            return false;
        }
        RemoteDeleteCourseMembership remoteDeleteCourseMembership = (RemoteDeleteCourseMembership) obj;
        return this.a == remoteDeleteCourseMembership.a && this.b == remoteDeleteCourseMembership.b;
    }

    public final int hashCode() {
        return Long.hashCode(this.b) + (Long.hashCode(this.a) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("RemoteDeleteCourseMembership(courseId=");
        sb.append(this.a);
        sb.append(", userId=");
        return android.support.v4.media.session.a.g(this.b, ")", sb);
    }
}

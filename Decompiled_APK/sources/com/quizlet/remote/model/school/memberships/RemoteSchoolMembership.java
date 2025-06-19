package com.quizlet.remote.model.school.memberships;

import androidx.compose.animation.d0;
import com.squareup.moshi.m;
import kotlin.Metadata;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class RemoteSchoolMembership {
    public final long a;
    public final long b;
    public final int c;
    public final long d;

    public RemoteSchoolMembership(long j, long j2, int i, long j3) {
        this.a = j;
        this.b = j2;
        this.c = i;
        this.d = j3;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof RemoteSchoolMembership)) {
            return false;
        }
        RemoteSchoolMembership remoteSchoolMembership = (RemoteSchoolMembership) obj;
        return this.a == remoteSchoolMembership.a && this.b == remoteSchoolMembership.b && this.c == remoteSchoolMembership.c && this.d == remoteSchoolMembership.d;
    }

    public final int hashCode() {
        return Long.hashCode(this.d) + d0.b(this.c, d0.d(Long.hashCode(this.a) * 31, 31, this.b), 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("RemoteSchoolMembership(userId=");
        sb.append(this.a);
        sb.append(", schoolId=");
        sb.append(this.b);
        sb.append(", relationshipType=");
        sb.append(this.c);
        sb.append(", lastModified=");
        return android.support.v4.media.session.a.g(this.d, ")", sb);
    }
}

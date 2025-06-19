package com.quizlet.remote.model.school.memberships;

import com.squareup.moshi.m;
import kotlin.Metadata;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class RemoteNewSchoolMembership {
    public final long a;
    public final int b;

    public RemoteNewSchoolMembership(int i, long j) {
        this.a = j;
        this.b = i;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof RemoteNewSchoolMembership)) {
            return false;
        }
        RemoteNewSchoolMembership remoteNewSchoolMembership = (RemoteNewSchoolMembership) obj;
        return this.a == remoteNewSchoolMembership.a && this.b == remoteNewSchoolMembership.b;
    }

    public final int hashCode() {
        return Integer.hashCode(this.b) + (Long.hashCode(this.a) * 31);
    }

    public final String toString() {
        return "RemoteNewSchoolMembership(schoolId=" + this.a + ", relationshipType=" + this.b + ")";
    }
}

package com.quizlet.remote.model.school.memberships;

import com.quizlet.db.data.models.persisted.fields.DBGroupFields;
import com.squareup.moshi.InterfaceC4853h;
import com.squareup.moshi.m;
import kotlin.Metadata;
import org.jetbrains.annotations.NotNull;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class RemoteDeleteSchoolMembership {
    public final long a;
    public final long b;

    public RemoteDeleteSchoolMembership(@InterfaceC4853h(name = "userId") long j, @InterfaceC4853h(name = DBGroupFields.Names.SCHOOL_ID) long j2) {
        this.a = j;
        this.b = j2;
    }

    @NotNull
    public final RemoteDeleteSchoolMembership copy(@InterfaceC4853h(name = "userId") long j, @InterfaceC4853h(name = DBGroupFields.Names.SCHOOL_ID) long j2) {
        return new RemoteDeleteSchoolMembership(j, j2);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof RemoteDeleteSchoolMembership)) {
            return false;
        }
        RemoteDeleteSchoolMembership remoteDeleteSchoolMembership = (RemoteDeleteSchoolMembership) obj;
        return this.a == remoteDeleteSchoolMembership.a && this.b == remoteDeleteSchoolMembership.b;
    }

    public final int hashCode() {
        return Long.hashCode(this.b) + (Long.hashCode(this.a) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("RemoteDeleteSchoolMembership(userId=");
        sb.append(this.a);
        sb.append(", schoolId=");
        return android.support.v4.media.session.a.g(this.b, ")", sb);
    }
}

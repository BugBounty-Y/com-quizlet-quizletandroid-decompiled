package com.quizlet.remote.model.classmembership;

import androidx.compose.animation.d0;
import com.quizlet.db.data.models.persisted.fields.DBGroupMembershipFields;
import com.squareup.moshi.InterfaceC4853h;
import com.squareup.moshi.m;
import kotlin.Metadata;
import org.jetbrains.annotations.NotNull;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class RemoteClassMembership {
    public final long a;
    public final long b;
    public final int c;
    public final int d;
    public final boolean e;
    public final int f;
    public final int g;

    public RemoteClassMembership(@InterfaceC4853h(name = "userId") long j, @InterfaceC4853h(name = DBGroupMembershipFields.Names.CLASS_ID) long j2, @InterfaceC4853h(name = "lastVisited") int i, @InterfaceC4853h(name = "level") int i2, @InterfaceC4853h(name = "receiveEmail") boolean z, @InterfaceC4853h(name = "timestamp") int i3, @InterfaceC4853h(name = "lastModified") int i4) {
        this.a = j;
        this.b = j2;
        this.c = i;
        this.d = i2;
        this.e = z;
        this.f = i3;
        this.g = i4;
    }

    @NotNull
    public final RemoteClassMembership copy(@InterfaceC4853h(name = "userId") long j, @InterfaceC4853h(name = DBGroupMembershipFields.Names.CLASS_ID) long j2, @InterfaceC4853h(name = "lastVisited") int i, @InterfaceC4853h(name = "level") int i2, @InterfaceC4853h(name = "receiveEmail") boolean z, @InterfaceC4853h(name = "timestamp") int i3, @InterfaceC4853h(name = "lastModified") int i4) {
        return new RemoteClassMembership(j, j2, i, i2, z, i3, i4);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof RemoteClassMembership)) {
            return false;
        }
        RemoteClassMembership remoteClassMembership = (RemoteClassMembership) obj;
        return this.a == remoteClassMembership.a && this.b == remoteClassMembership.b && this.c == remoteClassMembership.c && this.d == remoteClassMembership.d && this.e == remoteClassMembership.e && this.f == remoteClassMembership.f && this.g == remoteClassMembership.g;
    }

    public final int hashCode() {
        return Integer.hashCode(this.g) + d0.b(this.f, d0.g(d0.b(this.d, d0.b(this.c, d0.d(Long.hashCode(this.a) * 31, 31, this.b), 31), 31), 31, this.e), 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("RemoteClassMembership(userId=");
        sb.append(this.a);
        sb.append(", classId=");
        sb.append(this.b);
        sb.append(", lastVisitedSec=");
        sb.append(this.c);
        sb.append(", level=");
        sb.append(this.d);
        sb.append(", receiveEmail=");
        sb.append(this.e);
        sb.append(", timestampSec=");
        sb.append(this.f);
        sb.append(", lastModifiedSec=");
        return android.support.v4.media.session.a.r(sb, this.g, ")");
    }
}

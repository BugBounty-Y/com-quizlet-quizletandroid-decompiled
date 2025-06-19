package com.quizlet.remote.model.course;

import androidx.compose.animation.d0;
import com.quizlet.db.data.models.persisted.fields.DBGroupFields;
import com.squareup.moshi.InterfaceC4853h;
import com.squareup.moshi.m;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class RemoteNewCourseMembership {
    public final long a;
    public final Long b;
    public final long c;
    public final String d;

    public RemoteNewCourseMembership(@InterfaceC4853h(name = "courseId") long j, @InterfaceC4853h(name = DBGroupFields.Names.SCHOOL_ID) Long l, @InterfaceC4853h(name = "userId") long j2, @InterfaceC4853h(name = "folderName") String str) {
        this.a = j;
        this.b = l;
        this.c = j2;
        this.d = str;
    }

    @NotNull
    public final RemoteNewCourseMembership copy(@InterfaceC4853h(name = "courseId") long j, @InterfaceC4853h(name = DBGroupFields.Names.SCHOOL_ID) Long l, @InterfaceC4853h(name = "userId") long j2, @InterfaceC4853h(name = "folderName") String str) {
        return new RemoteNewCourseMembership(j, l, j2, str);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof RemoteNewCourseMembership)) {
            return false;
        }
        RemoteNewCourseMembership remoteNewCourseMembership = (RemoteNewCourseMembership) obj;
        return this.a == remoteNewCourseMembership.a && Intrinsics.b(this.b, remoteNewCourseMembership.b) && this.c == remoteNewCourseMembership.c && Intrinsics.b(this.d, remoteNewCourseMembership.d);
    }

    public final int hashCode() {
        int iHashCode = Long.hashCode(this.a) * 31;
        Long l = this.b;
        int iD = d0.d((iHashCode + (l == null ? 0 : l.hashCode())) * 31, 31, this.c);
        String str = this.d;
        return iD + (str != null ? str.hashCode() : 0);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("RemoteNewCourseMembership(courseId=");
        sb.append(this.a);
        sb.append(", schoolId=");
        sb.append(this.b);
        sb.append(", userId=");
        sb.append(this.c);
        sb.append(", folderName=");
        return android.support.v4.media.session.a.t(sb, this.d, ")");
    }

    public /* synthetic */ RemoteNewCourseMembership(long j, Long l, long j2, String str, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this(j, l, j2, (i & 8) != 0 ? null : str);
    }
}

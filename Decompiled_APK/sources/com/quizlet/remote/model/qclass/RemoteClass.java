package com.quizlet.remote.model.qclass;

import androidx.compose.animation.d0;
import com.onetrust.otpublishers.headless.Public.Keys.OTUXParamsKeys;
import com.quizlet.db.data.models.persisted.fields.DBFolderFields;
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
public final class RemoteClass {
    public final long a;
    public final String b;
    public final String c;
    public final long d;
    public final boolean e;
    public final boolean f;
    public final boolean g;
    public final long h;
    public final String i;
    public final long j;
    public final long k;
    public final Long l;
    public final Long m;

    public RemoteClass(@InterfaceC4853h(name = "id") long j, @InterfaceC4853h(name = "title") @NotNull String title, @InterfaceC4853h(name = OTUXParamsKeys.OT_UX_DESCRIPTION) @NotNull String description, @InterfaceC4853h(name = DBGroupFields.Names.SCHOOL_ID) long j2, @InterfaceC4853h(name = "restrictsPosting") boolean z, @InterfaceC4853h(name = "membersCanPost") boolean z2, @InterfaceC4853h(name = "membersCanInvite") boolean z3, @InterfaceC4853h(name = "creatorId") long j3, @InterfaceC4853h(name = DBGroupFields.Names.AUTO_JOIN_LINK) String str, @InterfaceC4853h(name = "_numMembers") long j4, @InterfaceC4853h(name = DBFolderFields.Names.NUM_SETS) long j5, @InterfaceC4853h(name = "timestamp") Long l, @InterfaceC4853h(name = "lastModified") Long l2) {
        Intrinsics.checkNotNullParameter(title, "title");
        Intrinsics.checkNotNullParameter(description, "description");
        this.a = j;
        this.b = title;
        this.c = description;
        this.d = j2;
        this.e = z;
        this.f = z2;
        this.g = z3;
        this.h = j3;
        this.i = str;
        this.j = j4;
        this.k = j5;
        this.l = l;
        this.m = l2;
    }

    @NotNull
    public final RemoteClass copy(@InterfaceC4853h(name = "id") long j, @InterfaceC4853h(name = "title") @NotNull String title, @InterfaceC4853h(name = OTUXParamsKeys.OT_UX_DESCRIPTION) @NotNull String description, @InterfaceC4853h(name = DBGroupFields.Names.SCHOOL_ID) long j2, @InterfaceC4853h(name = "restrictsPosting") boolean z, @InterfaceC4853h(name = "membersCanPost") boolean z2, @InterfaceC4853h(name = "membersCanInvite") boolean z3, @InterfaceC4853h(name = "creatorId") long j3, @InterfaceC4853h(name = DBGroupFields.Names.AUTO_JOIN_LINK) String str, @InterfaceC4853h(name = "_numMembers") long j4, @InterfaceC4853h(name = DBFolderFields.Names.NUM_SETS) long j5, @InterfaceC4853h(name = "timestamp") Long l, @InterfaceC4853h(name = "lastModified") Long l2) {
        Intrinsics.checkNotNullParameter(title, "title");
        Intrinsics.checkNotNullParameter(description, "description");
        return new RemoteClass(j, title, description, j2, z, z2, z3, j3, str, j4, j5, l, l2);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof RemoteClass)) {
            return false;
        }
        RemoteClass remoteClass = (RemoteClass) obj;
        return this.a == remoteClass.a && Intrinsics.b(this.b, remoteClass.b) && Intrinsics.b(this.c, remoteClass.c) && this.d == remoteClass.d && this.e == remoteClass.e && this.f == remoteClass.f && this.g == remoteClass.g && this.h == remoteClass.h && Intrinsics.b(this.i, remoteClass.i) && this.j == remoteClass.j && this.k == remoteClass.k && Intrinsics.b(this.l, remoteClass.l) && Intrinsics.b(this.m, remoteClass.m);
    }

    public final int hashCode() {
        int iD = d0.d(d0.g(d0.g(d0.g(d0.d(d0.e(d0.e(Long.hashCode(this.a) * 31, 31, this.b), 31, this.c), 31, this.d), 31, this.e), 31, this.f), 31, this.g), 31, this.h);
        String str = this.i;
        int iD2 = d0.d(d0.d((iD + (str == null ? 0 : str.hashCode())) * 31, 31, this.j), 31, this.k);
        Long l = this.l;
        int iHashCode = (iD2 + (l == null ? 0 : l.hashCode())) * 31;
        Long l2 = this.m;
        return iHashCode + (l2 != null ? l2.hashCode() : 0);
    }

    public final String toString() {
        return "RemoteClass(id=" + this.a + ", title=" + this.b + ", description=" + this.c + ", schoolId=" + this.d + ", restrictsPosting=" + this.e + ", membersCanPost=" + this.f + ", membersCanInvite=" + this.g + ", creatorId=" + this.h + ", autoJoinLink=" + this.i + ", numMembers=" + this.j + ", numSets=" + this.k + ", timestampSec=" + this.l + ", lastModifiedSec=" + this.m + ")";
    }

    public /* synthetic */ RemoteClass(long j, String str, String str2, long j2, boolean z, boolean z2, boolean z3, long j3, String str3, long j4, long j5, Long l, Long l2, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this(j, str, str2, j2, z, z2, z3, j3, (i & 256) != 0 ? null : str3, j4, j5, (i & 2048) != 0 ? null : l, (i & 4096) != 0 ? null : l2);
    }
}

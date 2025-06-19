package com.quizlet.remote.model.classset;

import androidx.compose.animation.d0;
import assistantMode.refactored.a;
import com.quizlet.db.data.models.persisted.fields.BaseDBModelFields;
import com.quizlet.db.data.models.persisted.fields.DBGroupFolderFields;
import com.quizlet.db.data.models.persisted.fields.DBGroupMembershipFields;
import com.squareup.moshi.InterfaceC4853h;
import com.squareup.moshi.m;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class RemoteClassSet {
    public final Long a;
    public final long b;
    public final long c;
    public final Long d;
    public final Long e;
    public final Boolean f;
    public final Long g;
    public final Long h;
    public final Long i;
    public final Boolean j;
    public final Boolean k;

    public RemoteClassSet(@InterfaceC4853h(name = "clientId") Long l, @InterfaceC4853h(name = "setId") long j, @InterfaceC4853h(name = DBGroupMembershipFields.Names.CLASS_ID) long j2, @InterfaceC4853h(name = "userId") Long l2, @InterfaceC4853h(name = "folderId") Long l3, @InterfaceC4853h(name = DBGroupFolderFields.Names.CAN_EDIT) Boolean bool, @InterfaceC4853h(name = "timestamp") Long l4, @InterfaceC4853h(name = "lastModified") Long l5, @InterfaceC4853h(name = BaseDBModelFields.Names.CLIENT_TIMESTAMP) Long l6, @InterfaceC4853h(name = "isDeleted") Boolean bool2, @InterfaceC4853h(name = "isDirty") Boolean bool3) {
        this.a = l;
        this.b = j;
        this.c = j2;
        this.d = l2;
        this.e = l3;
        this.f = bool;
        this.g = l4;
        this.h = l5;
        this.i = l6;
        this.j = bool2;
        this.k = bool3;
    }

    @NotNull
    public final RemoteClassSet copy(@InterfaceC4853h(name = "clientId") Long l, @InterfaceC4853h(name = "setId") long j, @InterfaceC4853h(name = DBGroupMembershipFields.Names.CLASS_ID) long j2, @InterfaceC4853h(name = "userId") Long l2, @InterfaceC4853h(name = "folderId") Long l3, @InterfaceC4853h(name = DBGroupFolderFields.Names.CAN_EDIT) Boolean bool, @InterfaceC4853h(name = "timestamp") Long l4, @InterfaceC4853h(name = "lastModified") Long l5, @InterfaceC4853h(name = BaseDBModelFields.Names.CLIENT_TIMESTAMP) Long l6, @InterfaceC4853h(name = "isDeleted") Boolean bool2, @InterfaceC4853h(name = "isDirty") Boolean bool3) {
        return new RemoteClassSet(l, j, j2, l2, l3, bool, l4, l5, l6, bool2, bool3);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof RemoteClassSet)) {
            return false;
        }
        RemoteClassSet remoteClassSet = (RemoteClassSet) obj;
        return Intrinsics.b(this.a, remoteClassSet.a) && this.b == remoteClassSet.b && this.c == remoteClassSet.c && Intrinsics.b(this.d, remoteClassSet.d) && Intrinsics.b(this.e, remoteClassSet.e) && Intrinsics.b(this.f, remoteClassSet.f) && Intrinsics.b(this.g, remoteClassSet.g) && Intrinsics.b(this.h, remoteClassSet.h) && Intrinsics.b(this.i, remoteClassSet.i) && Intrinsics.b(this.j, remoteClassSet.j) && Intrinsics.b(this.k, remoteClassSet.k);
    }

    public final int hashCode() {
        Long l = this.a;
        int iD = d0.d(d0.d((l == null ? 0 : l.hashCode()) * 31, 31, this.b), 31, this.c);
        Long l2 = this.d;
        int iHashCode = (iD + (l2 == null ? 0 : l2.hashCode())) * 31;
        Long l3 = this.e;
        int iHashCode2 = (iHashCode + (l3 == null ? 0 : l3.hashCode())) * 31;
        Boolean bool = this.f;
        int iHashCode3 = (iHashCode2 + (bool == null ? 0 : bool.hashCode())) * 31;
        Long l4 = this.g;
        int iHashCode4 = (iHashCode3 + (l4 == null ? 0 : l4.hashCode())) * 31;
        Long l5 = this.h;
        int iHashCode5 = (iHashCode4 + (l5 == null ? 0 : l5.hashCode())) * 31;
        Long l6 = this.i;
        int iHashCode6 = (iHashCode5 + (l6 == null ? 0 : l6.hashCode())) * 31;
        Boolean bool2 = this.j;
        int iHashCode7 = (iHashCode6 + (bool2 == null ? 0 : bool2.hashCode())) * 31;
        Boolean bool3 = this.k;
        return iHashCode7 + (bool3 != null ? bool3.hashCode() : 0);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("RemoteClassSet(localId=");
        sb.append(this.a);
        sb.append(", setId=");
        sb.append(this.b);
        sb.append(", classId=");
        sb.append(this.c);
        sb.append(", userId=");
        sb.append(this.d);
        sb.append(", folderId=");
        sb.append(this.e);
        sb.append(", canEdit=");
        sb.append(this.f);
        sb.append(", timestamp=");
        sb.append(this.g);
        sb.append(", lastModified=");
        sb.append(this.h);
        sb.append(", clientTimestamp=");
        sb.append(this.i);
        sb.append(", isDeleted=");
        sb.append(this.j);
        sb.append(", isDirty=");
        return a.k(sb, this.k, ")");
    }
}

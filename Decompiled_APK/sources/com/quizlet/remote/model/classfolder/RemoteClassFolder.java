package com.quizlet.remote.model.classfolder;

import androidx.compose.animation.d0;
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
public final class RemoteClassFolder {
    public final Long a;
    public final long b;
    public final long c;
    public final Boolean d;
    public final Long e;
    public final Long f;
    public final Long g;
    public final Boolean h;
    public final Boolean i;

    public RemoteClassFolder(@InterfaceC4853h(name = "clientId") Long l, @InterfaceC4853h(name = "folderId") long j, @InterfaceC4853h(name = DBGroupMembershipFields.Names.CLASS_ID) long j2, @InterfaceC4853h(name = DBGroupFolderFields.Names.CAN_EDIT) Boolean bool, @InterfaceC4853h(name = "addedTimestamp") Long l2, @InterfaceC4853h(name = "lastModified") Long l3, @InterfaceC4853h(name = BaseDBModelFields.Names.CLIENT_TIMESTAMP) Long l4, @InterfaceC4853h(name = "isDeleted") Boolean bool2, @InterfaceC4853h(name = "isDirty") Boolean bool3) {
        this.a = l;
        this.b = j;
        this.c = j2;
        this.d = bool;
        this.e = l2;
        this.f = l3;
        this.g = l4;
        this.h = bool2;
        this.i = bool3;
    }

    @NotNull
    public final RemoteClassFolder copy(@InterfaceC4853h(name = "clientId") Long l, @InterfaceC4853h(name = "folderId") long j, @InterfaceC4853h(name = DBGroupMembershipFields.Names.CLASS_ID) long j2, @InterfaceC4853h(name = DBGroupFolderFields.Names.CAN_EDIT) Boolean bool, @InterfaceC4853h(name = "addedTimestamp") Long l2, @InterfaceC4853h(name = "lastModified") Long l3, @InterfaceC4853h(name = BaseDBModelFields.Names.CLIENT_TIMESTAMP) Long l4, @InterfaceC4853h(name = "isDeleted") Boolean bool2, @InterfaceC4853h(name = "isDirty") Boolean bool3) {
        return new RemoteClassFolder(l, j, j2, bool, l2, l3, l4, bool2, bool3);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof RemoteClassFolder)) {
            return false;
        }
        RemoteClassFolder remoteClassFolder = (RemoteClassFolder) obj;
        return Intrinsics.b(this.a, remoteClassFolder.a) && this.b == remoteClassFolder.b && this.c == remoteClassFolder.c && Intrinsics.b(this.d, remoteClassFolder.d) && Intrinsics.b(this.e, remoteClassFolder.e) && Intrinsics.b(this.f, remoteClassFolder.f) && Intrinsics.b(this.g, remoteClassFolder.g) && Intrinsics.b(this.h, remoteClassFolder.h) && Intrinsics.b(this.i, remoteClassFolder.i);
    }

    public final int hashCode() {
        Long l = this.a;
        int iD = d0.d(d0.d((l == null ? 0 : l.hashCode()) * 31, 31, this.b), 31, this.c);
        Boolean bool = this.d;
        int iHashCode = (iD + (bool == null ? 0 : bool.hashCode())) * 31;
        Long l2 = this.e;
        int iHashCode2 = (iHashCode + (l2 == null ? 0 : l2.hashCode())) * 31;
        Long l3 = this.f;
        int iHashCode3 = (iHashCode2 + (l3 == null ? 0 : l3.hashCode())) * 31;
        Long l4 = this.g;
        int iHashCode4 = (iHashCode3 + (l4 == null ? 0 : l4.hashCode())) * 31;
        Boolean bool2 = this.h;
        int iHashCode5 = (iHashCode4 + (bool2 == null ? 0 : bool2.hashCode())) * 31;
        Boolean bool3 = this.i;
        return iHashCode5 + (bool3 != null ? bool3.hashCode() : 0);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("RemoteClassFolder(localId=");
        sb.append(this.a);
        sb.append(", folderId=");
        sb.append(this.b);
        sb.append(", classId=");
        sb.append(this.c);
        sb.append(", canEdit=");
        sb.append(this.d);
        sb.append(", timestamp=");
        sb.append(this.e);
        sb.append(", lastModified=");
        sb.append(this.f);
        sb.append(", clientTimestamp=");
        sb.append(this.g);
        sb.append(", isDeleted=");
        sb.append(this.h);
        sb.append(", isDirty=");
        return assistantMode.refactored.a.k(sb, this.i, ")");
    }
}

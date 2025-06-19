package com.quizlet.remote.model.notes;

import com.quizlet.remote.model.user.RemoteUser;
import com.squareup.moshi.m;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class RemoteStudyNote {
    public final String a;
    public final String b;
    public final RemoteUser c;
    public final Boolean d;

    public RemoteStudyNote(String str, String str2, RemoteUser remoteUser, Boolean bool) {
        this.a = str;
        this.b = str2;
        this.c = remoteUser;
        this.d = bool;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof RemoteStudyNote)) {
            return false;
        }
        RemoteStudyNote remoteStudyNote = (RemoteStudyNote) obj;
        return Intrinsics.b(this.a, remoteStudyNote.a) && Intrinsics.b(this.b, remoteStudyNote.b) && Intrinsics.b(this.c, remoteStudyNote.c) && Intrinsics.b(this.d, remoteStudyNote.d);
    }

    public final int hashCode() {
        String str = this.a;
        int iHashCode = (str == null ? 0 : str.hashCode()) * 31;
        String str2 = this.b;
        int iHashCode2 = (iHashCode + (str2 == null ? 0 : str2.hashCode())) * 31;
        RemoteUser remoteUser = this.c;
        int iHashCode3 = (iHashCode2 + (remoteUser == null ? 0 : remoteUser.hashCode())) * 31;
        Boolean bool = this.d;
        return iHashCode3 + (bool != null ? bool.hashCode() : 0);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("RemoteStudyNote(uuid=");
        sb.append(this.a);
        sb.append(", title=");
        sb.append(this.b);
        sb.append(", creator=");
        sb.append(this.c);
        sb.append(", isDeleted=");
        return assistantMode.refactored.a.k(sb, this.d, ")");
    }

    public /* synthetic */ RemoteStudyNote(String str, String str2, RemoteUser remoteUser, Boolean bool, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this(str, str2, remoteUser, (i & 8) != 0 ? null : bool);
    }
}

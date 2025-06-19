package com.quizlet.shared.models.api.notes;

import com.quizlet.shared.models.api.user.RemoteUser;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.internal.AbstractC5047c0;
import org.jetbrains.annotations.NotNull;

@kotlinx.serialization.f
@Metadata
/* loaded from: classes3.dex */
public final class RemoteStudyNote {

    @NotNull
    public static final Companion Companion = new Companion();
    public final String a;
    public final String b;
    public final RemoteUser c;
    public final Boolean d;
    public final Boolean e;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return RemoteStudyNote$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ RemoteStudyNote(int i, String str, String str2, RemoteUser remoteUser, Boolean bool, Boolean bool2) {
        if (7 != (i & 7)) {
            AbstractC5047c0.k(i, 7, RemoteStudyNote$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.a = str;
        this.b = str2;
        this.c = remoteUser;
        if ((i & 8) == 0) {
            this.d = null;
        } else {
            this.d = bool;
        }
        if ((i & 16) == 0) {
            this.e = null;
        } else {
            this.e = bool2;
        }
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof RemoteStudyNote)) {
            return false;
        }
        RemoteStudyNote remoteStudyNote = (RemoteStudyNote) obj;
        return Intrinsics.b(this.a, remoteStudyNote.a) && Intrinsics.b(this.b, remoteStudyNote.b) && Intrinsics.b(this.c, remoteStudyNote.c) && Intrinsics.b(this.d, remoteStudyNote.d) && Intrinsics.b(this.e, remoteStudyNote.e);
    }

    public final int hashCode() {
        String str = this.a;
        int iHashCode = (str == null ? 0 : str.hashCode()) * 31;
        String str2 = this.b;
        int iHashCode2 = (iHashCode + (str2 == null ? 0 : str2.hashCode())) * 31;
        RemoteUser remoteUser = this.c;
        int iHashCode3 = (iHashCode2 + (remoteUser == null ? 0 : remoteUser.hashCode())) * 31;
        Boolean bool = this.d;
        int iHashCode4 = (iHashCode3 + (bool == null ? 0 : bool.hashCode())) * 31;
        Boolean bool2 = this.e;
        return iHashCode4 + (bool2 != null ? bool2.hashCode() : 0);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("RemoteStudyNote(uuid=");
        sb.append(this.a);
        sb.append(", title=");
        sb.append(this.b);
        sb.append(", creator=");
        sb.append(this.c);
        sb.append(", isDeleted=");
        sb.append(this.d);
        sb.append(", redirectToWeb=");
        return assistantMode.refactored.a.k(sb, this.e, ")");
    }
}

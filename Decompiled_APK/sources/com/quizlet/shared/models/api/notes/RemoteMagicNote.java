package com.quizlet.shared.models.api.notes;

import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.internal.AbstractC5047c0;
import kotlinx.serialization.internal.C5048d;
import kotlinx.serialization.internal.q0;
import org.jetbrains.annotations.NotNull;

@kotlinx.serialization.f
@Metadata
/* loaded from: classes3.dex */
public final class RemoteMagicNote {

    @NotNull
    public static final Companion Companion = new Companion();
    public static final KSerializer[] k = {null, null, null, null, null, null, null, new C5048d(q0.a, 0), null, null};
    public final String a;
    public final Long b;
    public final String c;
    public final Boolean d;
    public final String e;
    public final String f;
    public final String g;
    public final List h;
    public final String i;
    public final Boolean j;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return RemoteMagicNote$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ RemoteMagicNote(int i, String str, Long l, String str2, Boolean bool, String str3, String str4, String str5, List list, String str6, Boolean bool2) {
        if (511 != (i & 511)) {
            AbstractC5047c0.k(i, 511, RemoteMagicNote$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.a = str;
        this.b = l;
        this.c = str2;
        this.d = bool;
        this.e = str3;
        this.f = str4;
        this.g = str5;
        this.h = list;
        this.i = str6;
        if ((i & com.google.android.gms.ads.g.MAX_CONTENT_URL_LENGTH) == 0) {
            this.j = null;
        } else {
            this.j = bool2;
        }
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof RemoteMagicNote)) {
            return false;
        }
        RemoteMagicNote remoteMagicNote = (RemoteMagicNote) obj;
        return Intrinsics.b(this.a, remoteMagicNote.a) && Intrinsics.b(this.b, remoteMagicNote.b) && Intrinsics.b(this.c, remoteMagicNote.c) && Intrinsics.b(this.d, remoteMagicNote.d) && Intrinsics.b(this.e, remoteMagicNote.e) && Intrinsics.b(this.f, remoteMagicNote.f) && Intrinsics.b(this.g, remoteMagicNote.g) && Intrinsics.b(this.h, remoteMagicNote.h) && Intrinsics.b(this.i, remoteMagicNote.i) && Intrinsics.b(this.j, remoteMagicNote.j);
    }

    public final int hashCode() {
        String str = this.a;
        int iHashCode = (str == null ? 0 : str.hashCode()) * 31;
        Long l = this.b;
        int iHashCode2 = (iHashCode + (l == null ? 0 : l.hashCode())) * 31;
        String str2 = this.c;
        int iHashCode3 = (iHashCode2 + (str2 == null ? 0 : str2.hashCode())) * 31;
        Boolean bool = this.d;
        int iHashCode4 = (iHashCode3 + (bool == null ? 0 : bool.hashCode())) * 31;
        String str3 = this.e;
        int iHashCode5 = (iHashCode4 + (str3 == null ? 0 : str3.hashCode())) * 31;
        String str4 = this.f;
        int iHashCode6 = (iHashCode5 + (str4 == null ? 0 : str4.hashCode())) * 31;
        String str5 = this.g;
        int iHashCode7 = (iHashCode6 + (str5 == null ? 0 : str5.hashCode())) * 31;
        List list = this.h;
        int iHashCode8 = (iHashCode7 + (list == null ? 0 : list.hashCode())) * 31;
        String str6 = this.i;
        int iHashCode9 = (iHashCode8 + (str6 == null ? 0 : str6.hashCode())) * 31;
        Boolean bool2 = this.j;
        return iHashCode9 + (bool2 != null ? bool2.hashCode() : 0);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("RemoteMagicNote(uuid=");
        sb.append(this.a);
        sb.append(", userId=");
        sb.append(this.b);
        sb.append(", documentType=");
        sb.append(this.c);
        sb.append(", isPrivate=");
        sb.append(this.d);
        sb.append(", language=");
        sb.append(this.e);
        sb.append(", extractedText=");
        sb.append(this.f);
        sb.append(", createdAt=");
        sb.append(this.g);
        sb.append(", artifactUuids=");
        sb.append(this.h);
        sb.append(", userModifiedAt=");
        sb.append(this.i);
        sb.append(", isDeleted=");
        return assistantMode.refactored.a.k(sb, this.j, ")");
    }
}

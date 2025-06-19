package com.quizlet.shared.models.api.notes;

import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.internal.AbstractC5047c0;
import org.jetbrains.annotations.NotNull;

@kotlinx.serialization.f
@Metadata
/* loaded from: classes3.dex */
public final class RemoteArtifact {

    @NotNull
    public static final Companion Companion = new Companion();
    public final String a;
    public final String b;
    public final Long c;
    public final String d;
    public final Integer e;
    public final String f;
    public final String g;
    public final String h;
    public final String i;
    public final Boolean j;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return RemoteArtifact$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ RemoteArtifact(int i, String str, String str2, Long l, String str3, Integer num, String str4, String str5, String str6, String str7, Boolean bool) {
        if (511 != (i & 511)) {
            AbstractC5047c0.k(i, 511, RemoteArtifact$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.a = str;
        this.b = str2;
        this.c = l;
        this.d = str3;
        this.e = num;
        this.f = str4;
        this.g = str5;
        this.h = str6;
        this.i = str7;
        if ((i & com.google.android.gms.ads.g.MAX_CONTENT_URL_LENGTH) == 0) {
            this.j = null;
        } else {
            this.j = bool;
        }
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof RemoteArtifact)) {
            return false;
        }
        RemoteArtifact remoteArtifact = (RemoteArtifact) obj;
        return Intrinsics.b(this.a, remoteArtifact.a) && Intrinsics.b(this.b, remoteArtifact.b) && Intrinsics.b(this.c, remoteArtifact.c) && Intrinsics.b(this.d, remoteArtifact.d) && Intrinsics.b(this.e, remoteArtifact.e) && Intrinsics.b(this.f, remoteArtifact.f) && Intrinsics.b(this.g, remoteArtifact.g) && Intrinsics.b(this.h, remoteArtifact.h) && Intrinsics.b(this.i, remoteArtifact.i) && Intrinsics.b(this.j, remoteArtifact.j);
    }

    public final int hashCode() {
        String str = this.a;
        int iHashCode = (str == null ? 0 : str.hashCode()) * 31;
        String str2 = this.b;
        int iHashCode2 = (iHashCode + (str2 == null ? 0 : str2.hashCode())) * 31;
        Long l = this.c;
        int iHashCode3 = (iHashCode2 + (l == null ? 0 : l.hashCode())) * 31;
        String str3 = this.d;
        int iHashCode4 = (iHashCode3 + (str3 == null ? 0 : str3.hashCode())) * 31;
        Integer num = this.e;
        int iHashCode5 = (iHashCode4 + (num == null ? 0 : num.hashCode())) * 31;
        String str4 = this.f;
        int iHashCode6 = (iHashCode5 + (str4 == null ? 0 : str4.hashCode())) * 31;
        String str5 = this.g;
        int iHashCode7 = (iHashCode6 + (str5 == null ? 0 : str5.hashCode())) * 31;
        String str6 = this.h;
        int iHashCode8 = (iHashCode7 + (str6 == null ? 0 : str6.hashCode())) * 31;
        String str7 = this.i;
        int iHashCode9 = (iHashCode8 + (str7 == null ? 0 : str7.hashCode())) * 31;
        Boolean bool = this.j;
        return iHashCode9 + (bool != null ? bool.hashCode() : 0);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("RemoteArtifact(uuid=");
        sb.append(this.a);
        sb.append(", noteUuid=");
        sb.append(this.b);
        sb.append(", userId=");
        sb.append(this.c);
        sb.append(", type=");
        sb.append(this.d);
        sb.append(", status=");
        sb.append(this.e);
        sb.append(", content=");
        sb.append(this.f);
        sb.append(", createdAt=");
        sb.append(this.g);
        sb.append(", updatedAt=");
        sb.append(this.h);
        sb.append(", history=");
        sb.append(this.i);
        sb.append(", isDeleted=");
        return assistantMode.refactored.a.k(sb, this.j, ")");
    }
}

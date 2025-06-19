package com.quizlet.shared.models.api.folders;

import com.google.android.gms.ads.g;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.f;
import kotlinx.serialization.internal.AbstractC5047c0;
import org.jetbrains.annotations.NotNull;

@f
@Metadata
/* loaded from: classes3.dex */
public final class RemoteFolder {

    @NotNull
    public static final Companion Companion = new Companion();
    public final Long a;
    public final Long b;
    public final String c;
    public final String d;
    public final Long e;
    public final Long f;
    public final Long g;
    public final Boolean h;
    public final String i;
    public final Boolean j;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return RemoteFolder$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ RemoteFolder(int i, Long l, Long l2, String str, String str2, Long l3, Long l4, Long l5, Boolean bool, String str3, Boolean bool2) {
        if (511 != (i & 511)) {
            AbstractC5047c0.k(i, 511, RemoteFolder$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.a = l;
        this.b = l2;
        this.c = str;
        this.d = str2;
        this.e = l3;
        this.f = l4;
        this.g = l5;
        this.h = bool;
        this.i = str3;
        if ((i & g.MAX_CONTENT_URL_LENGTH) == 0) {
            this.j = null;
        } else {
            this.j = bool2;
        }
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof RemoteFolder)) {
            return false;
        }
        RemoteFolder remoteFolder = (RemoteFolder) obj;
        return Intrinsics.b(this.a, remoteFolder.a) && Intrinsics.b(this.b, remoteFolder.b) && Intrinsics.b(this.c, remoteFolder.c) && Intrinsics.b(this.d, remoteFolder.d) && Intrinsics.b(this.e, remoteFolder.e) && Intrinsics.b(this.f, remoteFolder.f) && Intrinsics.b(this.g, remoteFolder.g) && Intrinsics.b(this.h, remoteFolder.h) && Intrinsics.b(this.i, remoteFolder.i) && Intrinsics.b(this.j, remoteFolder.j);
    }

    public final int hashCode() {
        Long l = this.a;
        int iHashCode = (l == null ? 0 : l.hashCode()) * 31;
        Long l2 = this.b;
        int iHashCode2 = (iHashCode + (l2 == null ? 0 : l2.hashCode())) * 31;
        String str = this.c;
        int iHashCode3 = (iHashCode2 + (str == null ? 0 : str.hashCode())) * 31;
        String str2 = this.d;
        int iHashCode4 = (iHashCode3 + (str2 == null ? 0 : str2.hashCode())) * 31;
        Long l3 = this.e;
        int iHashCode5 = (iHashCode4 + (l3 == null ? 0 : l3.hashCode())) * 31;
        Long l4 = this.f;
        int iHashCode6 = (iHashCode5 + (l4 == null ? 0 : l4.hashCode())) * 31;
        Long l5 = this.g;
        int iHashCode7 = (iHashCode6 + (l5 == null ? 0 : l5.hashCode())) * 31;
        Boolean bool = this.h;
        int iHashCode8 = (iHashCode7 + (bool == null ? 0 : bool.hashCode())) * 31;
        String str3 = this.i;
        int iHashCode9 = (iHashCode8 + (str3 == null ? 0 : str3.hashCode())) * 31;
        Boolean bool2 = this.j;
        return iHashCode9 + (bool2 != null ? bool2.hashCode() : 0);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("RemoteFolder(id=");
        sb.append(this.a);
        sb.append(", personId=");
        sb.append(this.b);
        sb.append(", name=");
        sb.append(this.c);
        sb.append(", description=");
        sb.append(this.d);
        sb.append(", timestamp=");
        sb.append(this.e);
        sb.append(", lastModified=");
        sb.append(this.f);
        sb.append(", numSets=");
        sb.append(this.g);
        sb.append(", isHidden=");
        sb.append(this.h);
        sb.append(", webUrl=");
        sb.append(this.i);
        sb.append(", isDeleted=");
        return assistantMode.refactored.a.k(sb, this.j, ")");
    }
}

package com.quizlet.shared.models.api.user;

import androidx.compose.animation.d0;
import assistantMode.refactored.a;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.f;
import kotlinx.serialization.internal.AbstractC5047c0;
import org.jetbrains.annotations.NotNull;

@f
@Metadata
/* loaded from: classes3.dex */
public final class RemoteUser {

    @NotNull
    public static final Companion Companion = new Companion();
    public final Long a;
    public final String b;
    public final Long c;
    public final Long d;
    public final Boolean e;
    public final Integer f;
    public final Integer g;
    public final Boolean h;
    public final String i;
    public final String j;
    public final String k;
    public final boolean l;
    public final Integer m;
    public final Integer n;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return RemoteUser$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ RemoteUser(int i, Long l, String str, Long l2, Long l3, Boolean bool, Integer num, Integer num2, Boolean bool2, String str2, String str3, String str4, boolean z, Integer num3, Integer num4) {
        if (751 != (i & 751)) {
            AbstractC5047c0.k(i, 751, RemoteUser$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.a = l;
        this.b = str;
        this.c = l2;
        this.d = l3;
        if ((i & 16) == 0) {
            this.e = Boolean.FALSE;
        } else {
            this.e = bool;
        }
        this.f = num;
        this.g = num2;
        this.h = bool2;
        if ((i & 256) == 0) {
            this.i = null;
        } else {
            this.i = str2;
        }
        this.j = str3;
        if ((i & 1024) == 0) {
            this.k = null;
        } else {
            this.k = str4;
        }
        this.l = (i & 2048) == 0 ? false : z;
        if ((i & 4096) == 0) {
            this.m = null;
        } else {
            this.m = num3;
        }
        if ((i & 8192) == 0) {
            this.n = null;
        } else {
            this.n = num4;
        }
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof RemoteUser)) {
            return false;
        }
        RemoteUser remoteUser = (RemoteUser) obj;
        return Intrinsics.b(this.a, remoteUser.a) && Intrinsics.b(this.b, remoteUser.b) && Intrinsics.b(this.c, remoteUser.c) && Intrinsics.b(this.d, remoteUser.d) && Intrinsics.b(this.e, remoteUser.e) && Intrinsics.b(this.f, remoteUser.f) && Intrinsics.b(this.g, remoteUser.g) && Intrinsics.b(this.h, remoteUser.h) && Intrinsics.b(this.i, remoteUser.i) && Intrinsics.b(this.j, remoteUser.j) && Intrinsics.b(this.k, remoteUser.k) && this.l == remoteUser.l && Intrinsics.b(this.m, remoteUser.m) && Intrinsics.b(this.n, remoteUser.n);
    }

    public final int hashCode() {
        Long l = this.a;
        int iHashCode = (l == null ? 0 : l.hashCode()) * 31;
        String str = this.b;
        int iHashCode2 = (iHashCode + (str == null ? 0 : str.hashCode())) * 31;
        Long l2 = this.c;
        int iHashCode3 = (iHashCode2 + (l2 == null ? 0 : l2.hashCode())) * 31;
        Long l3 = this.d;
        int iHashCode4 = (iHashCode3 + (l3 == null ? 0 : l3.hashCode())) * 31;
        Boolean bool = this.e;
        int iHashCode5 = (iHashCode4 + (bool == null ? 0 : bool.hashCode())) * 31;
        Integer num = this.f;
        int iHashCode6 = (iHashCode5 + (num == null ? 0 : num.hashCode())) * 31;
        Integer num2 = this.g;
        int iHashCode7 = (iHashCode6 + (num2 == null ? 0 : num2.hashCode())) * 31;
        Boolean bool2 = this.h;
        int iHashCode8 = (iHashCode7 + (bool2 == null ? 0 : bool2.hashCode())) * 31;
        String str2 = this.i;
        int iHashCode9 = (iHashCode8 + (str2 == null ? 0 : str2.hashCode())) * 31;
        String str3 = this.j;
        int iHashCode10 = (iHashCode9 + (str3 == null ? 0 : str3.hashCode())) * 31;
        String str4 = this.k;
        int iG = d0.g((iHashCode10 + (str4 == null ? 0 : str4.hashCode())) * 31, 31, this.l);
        Integer num3 = this.m;
        int iHashCode11 = (iG + (num3 == null ? 0 : num3.hashCode())) * 31;
        Integer num4 = this.n;
        return iHashCode11 + (num4 != null ? num4.hashCode() : 0);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("RemoteUser(id=");
        sb.append(this.a);
        sb.append(", username=");
        sb.append(this.b);
        sb.append(", timestamp=");
        sb.append(this.c);
        sb.append(", lastModified=");
        sb.append(this.d);
        sb.append(", isVerified=");
        sb.append(this.e);
        sb.append(", type=");
        sb.append(this.f);
        sb.append(", selfIdentifiedTeacherStatus=");
        sb.append(this.g);
        sb.append(", isLocked=");
        sb.append(this.h);
        sb.append(", imageURL=");
        sb.append(this.i);
        sb.append(", timeZone=");
        sb.append(this.j);
        sb.append(", profileImageId=");
        sb.append(this.k);
        sb.append(", isDeleted=");
        sb.append(this.l);
        sb.append(", numCreatedSets=");
        sb.append(this.m);
        sb.append(", numClassMemberships=");
        return a.l(sb, this.n, ")");
    }
}

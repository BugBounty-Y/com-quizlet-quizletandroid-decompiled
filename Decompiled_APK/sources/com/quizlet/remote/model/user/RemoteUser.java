package com.quizlet.remote.model.user;

import androidx.compose.animation.d0;
import com.quizlet.db.data.models.persisted.fields.DBUserFields;
import com.squareup.moshi.InterfaceC4853h;
import com.squareup.moshi.m;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class RemoteUser {
    public final long a;
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
    public final Boolean o;

    public RemoteUser(long j, String str, Long l, Long l2, Boolean bool, @InterfaceC4853h(name = DBUserFields.Names.USER_UPGRADE_TYPE) Integer num, @InterfaceC4853h(name = DBUserFields.Names.SELF_IDENTIFIED_USER_TYPE) Integer num2, Boolean bool2, @InterfaceC4853h(name = "_imageUrl") String str2, String str3, @InterfaceC4853h(name = DBUserFields.Names.PROFILE_IMAGE_ID) String str4, boolean z, @InterfaceC4853h(name = "_numCreatedSets") Integer num3, @InterfaceC4853h(name = "_numClassMemberships") Integer num4, @InterfaceC4853h(name = "_isUnderAge") Boolean bool3) {
        this.a = j;
        this.b = str;
        this.c = l;
        this.d = l2;
        this.e = bool;
        this.f = num;
        this.g = num2;
        this.h = bool2;
        this.i = str2;
        this.j = str3;
        this.k = str4;
        this.l = z;
        this.m = num3;
        this.n = num4;
        this.o = bool3;
    }

    @NotNull
    public final RemoteUser copy(long j, String str, Long l, Long l2, Boolean bool, @InterfaceC4853h(name = DBUserFields.Names.USER_UPGRADE_TYPE) Integer num, @InterfaceC4853h(name = DBUserFields.Names.SELF_IDENTIFIED_USER_TYPE) Integer num2, Boolean bool2, @InterfaceC4853h(name = "_imageUrl") String str2, String str3, @InterfaceC4853h(name = DBUserFields.Names.PROFILE_IMAGE_ID) String str4, boolean z, @InterfaceC4853h(name = "_numCreatedSets") Integer num3, @InterfaceC4853h(name = "_numClassMemberships") Integer num4, @InterfaceC4853h(name = "_isUnderAge") Boolean bool3) {
        return new RemoteUser(j, str, l, l2, bool, num, num2, bool2, str2, str3, str4, z, num3, num4, bool3);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof RemoteUser)) {
            return false;
        }
        RemoteUser remoteUser = (RemoteUser) obj;
        return this.a == remoteUser.a && Intrinsics.b(this.b, remoteUser.b) && Intrinsics.b(this.c, remoteUser.c) && Intrinsics.b(this.d, remoteUser.d) && Intrinsics.b(this.e, remoteUser.e) && Intrinsics.b(this.f, remoteUser.f) && Intrinsics.b(this.g, remoteUser.g) && Intrinsics.b(this.h, remoteUser.h) && Intrinsics.b(this.i, remoteUser.i) && Intrinsics.b(this.j, remoteUser.j) && Intrinsics.b(this.k, remoteUser.k) && this.l == remoteUser.l && Intrinsics.b(this.m, remoteUser.m) && Intrinsics.b(this.n, remoteUser.n) && Intrinsics.b(this.o, remoteUser.o);
    }

    public final int hashCode() {
        int iHashCode = Long.hashCode(this.a) * 31;
        String str = this.b;
        int iHashCode2 = (iHashCode + (str == null ? 0 : str.hashCode())) * 31;
        Long l = this.c;
        int iHashCode3 = (iHashCode2 + (l == null ? 0 : l.hashCode())) * 31;
        Long l2 = this.d;
        int iHashCode4 = (iHashCode3 + (l2 == null ? 0 : l2.hashCode())) * 31;
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
        int iHashCode12 = (iHashCode11 + (num4 == null ? 0 : num4.hashCode())) * 31;
        Boolean bool3 = this.o;
        return iHashCode12 + (bool3 != null ? bool3.hashCode() : 0);
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
        sb.append(", upgradeType=");
        sb.append(this.f);
        sb.append(", selfIdentifiedTeacherStatus=");
        sb.append(this.g);
        sb.append(", isLocked=");
        sb.append(this.h);
        sb.append(", imageURL=");
        sb.append(this.i);
        sb.append(", timeZone=");
        sb.append(this.j);
        sb.append(", profileImageID=");
        sb.append(this.k);
        sb.append(", isDeleted=");
        sb.append(this.l);
        sb.append(", numCreatedSets=");
        sb.append(this.m);
        sb.append(", numClassMemberships=");
        sb.append(this.n);
        sb.append(", isUnderAge=");
        return assistantMode.refactored.a.k(sb, this.o, ")");
    }

    public /* synthetic */ RemoteUser(long j, String str, Long l, Long l2, Boolean bool, Integer num, Integer num2, Boolean bool2, String str2, String str3, String str4, boolean z, Integer num3, Integer num4, Boolean bool3, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this(j, str, l, l2, (i & 16) != 0 ? Boolean.FALSE : bool, num, num2, bool2, str2, str3, str4, (i & 2048) != 0 ? false : z, num3, num4, (i & 16384) != 0 ? Boolean.FALSE : bool3);
    }
}

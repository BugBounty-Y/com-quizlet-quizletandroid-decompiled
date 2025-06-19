package com.quizlet.data.model;

import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;

@com.squareup.moshi.m(generateAdapter = true)
@Metadata
/* loaded from: classes2.dex */
public final class User {
    public final long a;
    public final String b;
    public final long c;
    public final long d;
    public final boolean e;
    public final int f;
    public final int g;
    public final boolean h;
    public final String i;
    public final String j;
    public final String k;
    public final boolean l;
    public final Integer m;
    public final Integer n;
    public final Boolean o;

    public User(long j, String username, long j2, long j3, boolean z, int i, int i2, boolean z2, String imageURL, String str, String str2, boolean z3, Integer num, Integer num2, Boolean bool) {
        Intrinsics.checkNotNullParameter(username, "username");
        Intrinsics.checkNotNullParameter(imageURL, "imageURL");
        this.a = j;
        this.b = username;
        this.c = j2;
        this.d = j3;
        this.e = z;
        this.f = i;
        this.g = i2;
        this.h = z2;
        this.i = imageURL;
        this.j = str;
        this.k = str2;
        this.l = z3;
        this.m = num;
        this.n = num2;
        this.o = bool;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof User)) {
            return false;
        }
        User user = (User) obj;
        return this.a == user.a && Intrinsics.b(this.b, user.b) && this.c == user.c && this.d == user.d && this.e == user.e && this.f == user.f && this.g == user.g && this.h == user.h && Intrinsics.b(this.i, user.i) && Intrinsics.b(this.j, user.j) && Intrinsics.b(this.k, user.k) && this.l == user.l && Intrinsics.b(this.m, user.m) && Intrinsics.b(this.n, user.n) && Intrinsics.b(this.o, user.o);
    }

    public final int hashCode() {
        int iE = androidx.compose.animation.d0.e(androidx.compose.animation.d0.g(androidx.compose.animation.d0.b(this.g, androidx.compose.animation.d0.b(this.f, androidx.compose.animation.d0.g(androidx.compose.animation.d0.d(androidx.compose.animation.d0.d(androidx.compose.animation.d0.e(Long.hashCode(this.a) * 31, 31, this.b), 31, this.c), 31, this.d), 31, this.e), 31), 31), 31, this.h), 31, this.i);
        String str = this.j;
        int iHashCode = (iE + (str == null ? 0 : str.hashCode())) * 31;
        String str2 = this.k;
        int iG = androidx.compose.animation.d0.g((iHashCode + (str2 == null ? 0 : str2.hashCode())) * 31, 31, this.l);
        Integer num = this.m;
        int iHashCode2 = (iG + (num == null ? 0 : num.hashCode())) * 31;
        Integer num2 = this.n;
        int iHashCode3 = (iHashCode2 + (num2 == null ? 0 : num2.hashCode())) * 31;
        Boolean bool = this.o;
        return iHashCode3 + (bool != null ? bool.hashCode() : 0);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("User(id=");
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

    public /* synthetic */ User(long j, String str, long j2, long j3, boolean z, int i, int i2, boolean z2, String str2, String str3, String str4, boolean z3, Integer num, Integer num2, Boolean bool, int i3, DefaultConstructorMarker defaultConstructorMarker) {
        this(j, str, j2, j3, z, i, i2, z2, str2, str3, str4, z3, num, num2, (i3 & 16384) != 0 ? Boolean.FALSE : bool);
    }
}

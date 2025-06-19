package com.quizlet.data.model;

import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.data.model.h1, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C4133h1 {
    public final long a;
    public final String b;
    public final String c;
    public final long d;
    public final boolean e;
    public final boolean f;
    public final boolean g;
    public final long h;
    public final String i;
    public final long j;
    public final long k;
    public final Long l;
    public final Long m;

    public C4133h1(long j, String title, String description, long j2, boolean z, boolean z2, boolean z3, long j3, String str, long j4, long j5, Long l, Long l2) {
        Intrinsics.checkNotNullParameter(title, "title");
        Intrinsics.checkNotNullParameter(description, "description");
        this.a = j;
        this.b = title;
        this.c = description;
        this.d = j2;
        this.e = z;
        this.f = z2;
        this.g = z3;
        this.h = j3;
        this.i = str;
        this.j = j4;
        this.k = j5;
        this.l = l;
        this.m = l2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C4133h1)) {
            return false;
        }
        C4133h1 c4133h1 = (C4133h1) obj;
        return this.a == c4133h1.a && Intrinsics.b(this.b, c4133h1.b) && Intrinsics.b(this.c, c4133h1.c) && this.d == c4133h1.d && this.e == c4133h1.e && this.f == c4133h1.f && this.g == c4133h1.g && this.h == c4133h1.h && Intrinsics.b(this.i, c4133h1.i) && this.j == c4133h1.j && this.k == c4133h1.k && Intrinsics.b(this.l, c4133h1.l) && Intrinsics.b(this.m, c4133h1.m);
    }

    public final int hashCode() {
        int iD = androidx.compose.animation.d0.d(androidx.compose.animation.d0.g(androidx.compose.animation.d0.g(androidx.compose.animation.d0.g(androidx.compose.animation.d0.d(androidx.compose.animation.d0.e(androidx.compose.animation.d0.e(Long.hashCode(this.a) * 31, 31, this.b), 31, this.c), 31, this.d), 31, this.e), 31, this.f), 31, this.g), 31, this.h);
        String str = this.i;
        int iD2 = androidx.compose.animation.d0.d(androidx.compose.animation.d0.d((iD + (str == null ? 0 : str.hashCode())) * 31, 31, this.j), 31, this.k);
        Long l = this.l;
        int iHashCode = (iD2 + (l == null ? 0 : l.hashCode())) * 31;
        Long l2 = this.m;
        return iHashCode + (l2 != null ? l2.hashCode() : 0);
    }

    public final String toString() {
        return "QClass(id=" + this.a + ", title=" + this.b + ", description=" + this.c + ", schoolId=" + this.d + ", restrictsPosting=" + this.e + ", membersCanPost=" + this.f + ", membersCanInvite=" + this.g + ", creatorId=" + this.h + ", autoJoinLink=" + this.i + ", numMembers=" + this.j + ", numSets=" + this.k + ", timestampSec=" + this.l + ", lastModifiedSec=" + this.m + ")";
    }
}

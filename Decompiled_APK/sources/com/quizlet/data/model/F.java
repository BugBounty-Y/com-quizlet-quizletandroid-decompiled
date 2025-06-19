package com.quizlet.data.model;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class F {
    public final Long a;
    public final long b;
    public final long c;
    public final long d;
    public final Long e;
    public final boolean f;
    public final long g;
    public final Boolean h;
    public final Long i;
    public final long j;
    public final boolean k;

    public F(Long l, long j, long j2, long j3, Long l2, boolean z, long j4, Boolean bool, Long l3, long j5, boolean z2) {
        this.a = l;
        this.b = j;
        this.c = j2;
        this.d = j3;
        this.e = l2;
        this.f = z;
        this.g = j4;
        this.h = bool;
        this.i = l3;
        this.j = j5;
        this.k = z2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof F)) {
            return false;
        }
        F f = (F) obj;
        return Intrinsics.b(this.a, f.a) && this.b == f.b && this.c == f.c && this.d == f.d && Intrinsics.b(this.e, f.e) && this.f == f.f && this.g == f.g && Intrinsics.b(this.h, f.h) && Intrinsics.b(this.i, f.i) && this.j == f.j && this.k == f.k;
    }

    public final int hashCode() {
        Long l = this.a;
        int iD = androidx.compose.animation.d0.d(androidx.compose.animation.d0.d(androidx.compose.animation.d0.d((l == null ? 0 : l.hashCode()) * 31, 31, this.b), 31, this.c), 31, this.d);
        Long l2 = this.e;
        int iD2 = androidx.compose.animation.d0.d(androidx.compose.animation.d0.g((iD + (l2 == null ? 0 : l2.hashCode())) * 31, 31, this.f), 31, this.g);
        Boolean bool = this.h;
        int iHashCode = (iD2 + (bool == null ? 0 : bool.hashCode())) * 31;
        Long l3 = this.i;
        return Boolean.hashCode(this.k) + androidx.compose.animation.d0.d((iHashCode + (l3 != null ? l3.hashCode() : 0)) * 31, 31, this.j);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("ClassSet(localId=");
        sb.append(this.a);
        sb.append(", classId=");
        sb.append(this.b);
        sb.append(", setId=");
        sb.append(this.c);
        sb.append(", userId=");
        sb.append(this.d);
        sb.append(", folderId=");
        sb.append(this.e);
        sb.append(", canEdit=");
        sb.append(this.f);
        sb.append(", timestampSec=");
        sb.append(this.g);
        sb.append(", isDeleted=");
        sb.append(this.h);
        sb.append(", clientTimestampSec=");
        sb.append(this.i);
        sb.append(", lastModifiedSec=");
        sb.append(this.j);
        sb.append(", isDirty=");
        return android.support.v4.media.session.a.o(")", sb, this.k);
    }
}

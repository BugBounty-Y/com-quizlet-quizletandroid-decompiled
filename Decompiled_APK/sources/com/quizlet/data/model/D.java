package com.quizlet.data.model;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class D {
    public final Long a;
    public final long b;
    public final long c;
    public final boolean d;
    public final long e;
    public final Boolean f;
    public final Long g;
    public final long h;
    public final boolean i;

    public D(Long l, long j, long j2, boolean z, long j3, Boolean bool, Long l2, long j4, boolean z2) {
        this.a = l;
        this.b = j;
        this.c = j2;
        this.d = z;
        this.e = j3;
        this.f = bool;
        this.g = l2;
        this.h = j4;
        this.i = z2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof D)) {
            return false;
        }
        D d = (D) obj;
        return Intrinsics.b(this.a, d.a) && this.b == d.b && this.c == d.c && this.d == d.d && this.e == d.e && Intrinsics.b(this.f, d.f) && Intrinsics.b(this.g, d.g) && this.h == d.h && this.i == d.i;
    }

    public final int hashCode() {
        Long l = this.a;
        int iD = androidx.compose.animation.d0.d(androidx.compose.animation.d0.g(androidx.compose.animation.d0.d(androidx.compose.animation.d0.d((l == null ? 0 : l.hashCode()) * 31, 31, this.b), 31, this.c), 31, this.d), 31, this.e);
        Boolean bool = this.f;
        int iHashCode = (iD + (bool == null ? 0 : bool.hashCode())) * 31;
        Long l2 = this.g;
        return Boolean.hashCode(this.i) + androidx.compose.animation.d0.d((iHashCode + (l2 != null ? l2.hashCode() : 0)) * 31, 31, this.h);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("ClassFolder(localId=");
        sb.append(this.a);
        sb.append(", classId=");
        sb.append(this.b);
        sb.append(", folderId=");
        sb.append(this.c);
        sb.append(", canEdit=");
        sb.append(this.d);
        sb.append(", timestampSec=");
        sb.append(this.e);
        sb.append(", isDeleted=");
        sb.append(this.f);
        sb.append(", clientTimestampSec=");
        sb.append(this.g);
        sb.append(", lastModifiedSec=");
        sb.append(this.h);
        sb.append(", isDirty=");
        return android.support.v4.media.session.a.o(")", sb, this.i);
    }
}

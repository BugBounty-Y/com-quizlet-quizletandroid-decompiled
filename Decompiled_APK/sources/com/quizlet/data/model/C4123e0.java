package com.quizlet.data.model;

import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.data.model.e0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C4123e0 {
    public final Long a;
    public final long b;
    public final long c;
    public final long d;
    public final Boolean e;
    public final Long f;
    public final long g;
    public final boolean h;

    public C4123e0(Long l, long j, long j2, long j3, Boolean bool, Long l2, long j4, boolean z) {
        this.a = l;
        this.b = j;
        this.c = j2;
        this.d = j3;
        this.e = bool;
        this.f = l2;
        this.g = j4;
        this.h = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C4123e0)) {
            return false;
        }
        C4123e0 c4123e0 = (C4123e0) obj;
        return Intrinsics.b(this.a, c4123e0.a) && this.b == c4123e0.b && this.c == c4123e0.c && this.d == c4123e0.d && Intrinsics.b(this.e, c4123e0.e) && Intrinsics.b(this.f, c4123e0.f) && this.g == c4123e0.g && this.h == c4123e0.h;
    }

    public final int hashCode() {
        Long l = this.a;
        int iD = androidx.compose.animation.d0.d(androidx.compose.animation.d0.d(androidx.compose.animation.d0.d((l == null ? 0 : l.hashCode()) * 31, 31, this.b), 31, this.c), 31, this.d);
        Boolean bool = this.e;
        int iHashCode = (iD + (bool == null ? 0 : bool.hashCode())) * 31;
        Long l2 = this.f;
        return Boolean.hashCode(this.h) + androidx.compose.animation.d0.d((iHashCode + (l2 != null ? l2.hashCode() : 0)) * 31, 31, this.g);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("FolderSet(localId=");
        sb.append(this.a);
        sb.append(", setId=");
        sb.append(this.b);
        sb.append(", folderId=");
        sb.append(this.c);
        sb.append(", timestamp=");
        sb.append(this.d);
        sb.append(", isDeleted=");
        sb.append(this.e);
        sb.append(", clientTimestamp=");
        sb.append(this.f);
        sb.append(", lastModified=");
        sb.append(this.g);
        sb.append(", isDirty=");
        return android.support.v4.media.session.a.o(")", sb, this.h);
    }
}

package com.quizlet.data.model;

import com.quizlet.generated.enums.EnumC4526v;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class E {
    public final long a;
    public final long b;
    public final int c;
    public final EnumC4526v d;
    public final boolean e;
    public final int f;
    public final int g;
    public final boolean h;
    public final boolean i;

    public E(long j, long j2, int i, EnumC4526v level, boolean z, int i2, int i3) {
        Intrinsics.checkNotNullParameter(level, "level");
        this.a = j;
        this.b = j2;
        this.c = i;
        this.d = level;
        this.e = z;
        this.f = i2;
        this.g = i3;
        this.h = level.a() >= EnumC4526v.ADMIN.a();
        this.i = level.a() >= EnumC4526v.MEMBER.a();
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof E)) {
            return false;
        }
        E e = (E) obj;
        return this.a == e.a && this.b == e.b && this.c == e.c && this.d == e.d && this.e == e.e && this.f == e.f && this.g == e.g;
    }

    public final int hashCode() {
        return Integer.hashCode(this.g) + androidx.compose.animation.d0.b(this.f, androidx.compose.animation.d0.g((this.d.hashCode() + androidx.compose.animation.d0.b(this.c, androidx.compose.animation.d0.d(Long.hashCode(this.a) * 31, 31, this.b), 31)) * 31, 31, this.e), 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("ClassMembership(userId=");
        sb.append(this.a);
        sb.append(", classId=");
        sb.append(this.b);
        sb.append(", lastVisitedSec=");
        sb.append(this.c);
        sb.append(", level=");
        sb.append(this.d);
        sb.append(", receiveEmail=");
        sb.append(this.e);
        sb.append(", timestampSec=");
        sb.append(this.f);
        sb.append(", lastModifiedSec=");
        return android.support.v4.media.session.a.r(sb, this.g, ")");
    }
}

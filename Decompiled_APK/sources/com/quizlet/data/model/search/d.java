package com.quizlet.data.model.search;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class d {
    public final long a;
    public final int b;
    public final int c;
    public final String d;
    public final boolean e;
    public final Long f;
    public final String g;

    public d(int i, int i2, String timeUnit, boolean z, Long l, String str, long j) {
        Intrinsics.checkNotNullParameter(timeUnit, "timeUnit");
        this.a = j;
        this.b = i;
        this.c = i2;
        this.d = timeUnit;
        this.e = z;
        this.f = l;
        this.g = str;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof d)) {
            return false;
        }
        d dVar = (d) obj;
        return this.a == dVar.a && this.b == dVar.b && this.c == dVar.c && Intrinsics.b(this.d, dVar.d) && this.e == dVar.e && Intrinsics.b(this.f, dVar.f) && Intrinsics.b(this.g, dVar.g);
    }

    public final int hashCode() {
        int iG = d0.g(d0.e(d0.b(this.c, d0.b(this.b, Long.hashCode(this.a) * 31, 31), 31), 31, this.d), 31, this.e);
        Long l = this.f;
        int iHashCode = (iG + (l == null ? 0 : l.hashCode())) * 31;
        String str = this.g;
        return iHashCode + (str != null ? str.hashCode() : 0);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("SocialSignalForSet(studiableId=");
        sb.append(this.a);
        sb.append(", numStudiers=");
        sb.append(this.b);
        sb.append(", time=");
        sb.append(this.c);
        sb.append(", timeUnit=");
        sb.append(this.d);
        sb.append(", largeTimeRange=");
        sb.append(this.e);
        sb.append(", schoolId=");
        sb.append(this.f);
        sb.append(", schoolName=");
        return android.support.v4.media.session.a.t(sb, this.g, ")");
    }
}

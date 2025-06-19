package com.quizlet.remote.model.course;

import androidx.compose.animation.d0;
import com.squareup.moshi.m;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class RemoteCourse {
    public final long a;
    public final String b;
    public final String c;
    public final int d;
    public final String e;
    public final Long f;

    public RemoteCourse(long j, String str, String str2, int i, String name, Long l) {
        Intrinsics.checkNotNullParameter(name, "name");
        this.a = j;
        this.b = str;
        this.c = str2;
        this.d = i;
        this.e = name;
        this.f = l;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof RemoteCourse)) {
            return false;
        }
        RemoteCourse remoteCourse = (RemoteCourse) obj;
        return this.a == remoteCourse.a && Intrinsics.b(this.b, remoteCourse.b) && Intrinsics.b(this.c, remoteCourse.c) && this.d == remoteCourse.d && Intrinsics.b(this.e, remoteCourse.e) && Intrinsics.b(this.f, remoteCourse.f);
    }

    public final int hashCode() {
        int iHashCode = Long.hashCode(this.a) * 31;
        String str = this.b;
        int iHashCode2 = (iHashCode + (str == null ? 0 : str.hashCode())) * 31;
        String str2 = this.c;
        int iE = d0.e(d0.b(this.d, (iHashCode2 + (str2 == null ? 0 : str2.hashCode())) * 31, 31), 31, this.e);
        Long l = this.f;
        return iE + (l != null ? l.hashCode() : 0);
    }

    public final String toString() {
        return "RemoteCourse(id=" + this.a + ", code=" + this.b + ", countryCode=" + this.c + ", lastModified=" + this.d + ", name=" + this.e + ", timestamp=" + this.f + ")";
    }
}

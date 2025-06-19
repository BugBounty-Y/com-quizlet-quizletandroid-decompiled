package com.quizlet.data.model;

import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@com.squareup.moshi.m(generateAdapter = true)
@Metadata
/* loaded from: classes2.dex */
public final class Course {
    public final long a;
    public final String b;
    public final String c;
    public final int d;
    public final String e;
    public final long f;

    public Course(int i, long j, long j2, String str, String str2, String name) {
        Intrinsics.checkNotNullParameter(name, "name");
        this.a = j;
        this.b = str;
        this.c = str2;
        this.d = i;
        this.e = name;
        this.f = j2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof Course)) {
            return false;
        }
        Course course = (Course) obj;
        return this.a == course.a && Intrinsics.b(this.b, course.b) && Intrinsics.b(this.c, course.c) && this.d == course.d && Intrinsics.b(this.e, course.e) && this.f == course.f;
    }

    public final int hashCode() {
        int iHashCode = Long.hashCode(this.a) * 31;
        String str = this.b;
        int iHashCode2 = (iHashCode + (str == null ? 0 : str.hashCode())) * 31;
        String str2 = this.c;
        return Long.hashCode(this.f) + androidx.compose.animation.d0.e(androidx.compose.animation.d0.b(this.d, (iHashCode2 + (str2 != null ? str2.hashCode() : 0)) * 31, 31), 31, this.e);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("Course(id=");
        sb.append(this.a);
        sb.append(", code=");
        sb.append(this.b);
        sb.append(", countryCode=");
        sb.append(this.c);
        sb.append(", lastModified=");
        sb.append(this.d);
        sb.append(", name=");
        sb.append(this.e);
        sb.append(", timestamp=");
        return android.support.v4.media.session.a.g(this.f, ")", sb);
    }
}

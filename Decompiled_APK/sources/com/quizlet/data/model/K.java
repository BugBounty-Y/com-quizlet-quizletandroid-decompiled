package com.quizlet.data.model;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class K {
    public final School a;
    public final Course b;

    public K(School school, Course course) {
        Intrinsics.checkNotNullParameter(school, "school");
        Intrinsics.checkNotNullParameter(course, "course");
        this.a = school;
        this.b = course;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof K)) {
            return false;
        }
        K k = (K) obj;
        return Intrinsics.b(this.a, k.a) && Intrinsics.b(this.b, k.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "CourseInstance(school=" + this.a + ", course=" + this.b + ")";
    }
}

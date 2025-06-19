package com.quizlet.data.model;

import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.data.model.r1, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C4162r1 extends AbstractC4165s1 {
    public final Object a;
    public final School b;
    public final Course c;

    public C4162r1(List recommendedStudySets, School school, Course course) {
        Intrinsics.checkNotNullParameter(recommendedStudySets, "recommendedStudySets");
        this.a = recommendedStudySets;
        this.b = school;
        this.c = course;
    }

    /* JADX WARN: Type inference failed for: r0v0, types: [java.lang.Object, java.util.List] */
    @Override // com.quizlet.data.model.AbstractC4165s1
    public final List a() {
        return this.a;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C4162r1)) {
            return false;
        }
        C4162r1 c4162r1 = (C4162r1) obj;
        return Intrinsics.b(this.a, c4162r1.a) && Intrinsics.b(this.b, c4162r1.b) && Intrinsics.b(this.c, c4162r1.c);
    }

    public final int hashCode() {
        int iHashCode = this.a.hashCode() * 31;
        School school = this.b;
        int iHashCode2 = (iHashCode + (school == null ? 0 : school.hashCode())) * 31;
        Course course = this.c;
        return iHashCode2 + (course != null ? course.hashCode() : 0);
    }

    public final String toString() {
        return "RecommendedSchoolCourseSets(recommendedStudySets=" + this.a + ", schoolSource=" + this.b + ", courseSource=" + this.c + ")";
    }
}

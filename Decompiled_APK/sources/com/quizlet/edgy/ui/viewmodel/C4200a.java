package com.quizlet.edgy.ui.viewmodel;

import com.quizlet.data.model.Course;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.edgy.ui.viewmodel.a, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C4200a {
    public final Course a;

    public C4200a(Course course) {
        Intrinsics.checkNotNullParameter(course, "course");
        this.a = course;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof C4200a) && Intrinsics.b(this.a, ((C4200a) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "ReturnToAddSchoolAndCourses(course=" + this.a + ")";
    }
}

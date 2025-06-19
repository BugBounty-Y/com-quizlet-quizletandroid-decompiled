package com.quizlet.features.infra.folder.create.coursefolder.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class e implements j {
    public final com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.viewmodel.a a;

    public e(com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.viewmodel.a courseData) {
        Intrinsics.checkNotNullParameter(courseData, "courseData");
        this.a = courseData;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof e) && Intrinsics.b(this.a, ((e) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "CourseSelected(courseData=" + this.a + ")";
    }
}

package com.quizlet.edgy.ui.viewmodel;

import com.quizlet.data.model.School;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class t {
    public final School a;

    public t(School school) {
        Intrinsics.checkNotNullParameter(school, "school");
        this.a = school;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof t) && Intrinsics.b(this.a, ((t) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "ReturnToAddSchoolAndCourses(school=" + this.a + ")";
    }
}

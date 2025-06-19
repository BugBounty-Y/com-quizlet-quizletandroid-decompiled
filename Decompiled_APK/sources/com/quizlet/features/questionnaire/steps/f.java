package com.quizlet.features.questionnaire.steps;

import com.quizlet.features.questionnaire.navigation.StepModel;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class f extends g {
    public final StepModel.SchoolCourse a;
    public final com.quizlet.data.interactor.course.a b;

    public f(StepModel.SchoolCourse model, com.quizlet.data.interactor.course.a shim) {
        Intrinsics.checkNotNullParameter(model, "model");
        Intrinsics.checkNotNullParameter(shim, "shim");
        this.a = model;
        this.b = shim;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof f)) {
            return false;
        }
        f fVar = (f) obj;
        return this.a.equals(fVar.a) && Intrinsics.b(this.b, fVar.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "SchoolCourseParams(model=" + this.a + ", shim=" + this.b + ")";
    }
}

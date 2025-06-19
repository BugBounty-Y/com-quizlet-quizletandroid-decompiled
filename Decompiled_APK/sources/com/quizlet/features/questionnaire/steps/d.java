package com.quizlet.features.questionnaire.steps;

import com.quizlet.features.questionnaire.navigation.StepModel;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class d extends g {
    public final StepModel.Exams a;
    public final com.quizlet.data.interactor.course.a b;

    public d(StepModel.Exams model, com.quizlet.data.interactor.course.a shim) {
        Intrinsics.checkNotNullParameter(model, "model");
        Intrinsics.checkNotNullParameter(shim, "shim");
        this.a = model;
        this.b = shim;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof d)) {
            return false;
        }
        d dVar = (d) obj;
        return this.a.equals(dVar.a) && Intrinsics.b(this.b, dVar.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "ExamsParams(model=" + this.a + ", shim=" + this.b + ")";
    }
}

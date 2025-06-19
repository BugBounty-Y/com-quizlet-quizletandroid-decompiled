package com.quizlet.features.questionnaire.steps;

import com.quizlet.features.questionnaire.navigation.StepModel;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class e extends g {
    public final StepModel.Intro a;
    public final com.quizlet.data.interactor.course.a b;

    public e(StepModel.Intro model, com.quizlet.data.interactor.course.a shim) {
        Intrinsics.checkNotNullParameter(model, "model");
        Intrinsics.checkNotNullParameter(shim, "shim");
        this.a = model;
        this.b = shim;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof e)) {
            return false;
        }
        e eVar = (e) obj;
        return this.a.equals(eVar.a) && Intrinsics.b(this.b, eVar.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "IntroParams(model=" + this.a + ", shim=" + this.b + ")";
    }
}

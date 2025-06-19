package com.quizlet.quizletandroid.ui.onboarding;

import com.quizlet.features.questionnaire.navigation.QuestionnaireModel;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class c {
    public final QuestionnaireModel a;

    public c(QuestionnaireModel questionnaireModel) {
        this.a = questionnaireModel;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof c) && Intrinsics.b(this.a, ((c) obj).a);
    }

    public final int hashCode() {
        QuestionnaireModel questionnaireModel = this.a;
        if (questionnaireModel == null) {
            return 0;
        }
        return questionnaireModel.hashCode();
    }

    public final String toString() {
        return "SetModel(model=" + this.a + ")";
    }
}

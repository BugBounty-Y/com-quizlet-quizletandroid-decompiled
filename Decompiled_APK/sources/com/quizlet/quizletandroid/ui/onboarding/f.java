package com.quizlet.quizletandroid.ui.onboarding;

import com.google.android.gms.internal.mlkit_vision_document_scanner.B5;
import com.quizlet.features.questionnaire.navigation.QuestionnaireModel;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class f extends B5 {
    public final QuestionnaireModel a;

    public f(QuestionnaireModel model) {
        Intrinsics.checkNotNullParameter(model, "model");
        this.a = model;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof f) && Intrinsics.b(this.a, ((f) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "Questionnaire(model=" + this.a + ")";
    }
}

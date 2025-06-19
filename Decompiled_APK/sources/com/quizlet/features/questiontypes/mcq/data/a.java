package com.quizlet.features.questiontypes.mcq.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a {
    public final com.quizlet.features.infra.models.studymodeshared.a a;
    public final com.quizlet.features.questiontypes.composables.a b;

    public a(com.quizlet.features.infra.models.studymodeshared.a choiceViewData, com.quizlet.features.questiontypes.composables.a buttonStatus) {
        Intrinsics.checkNotNullParameter(choiceViewData, "choiceViewData");
        Intrinsics.checkNotNullParameter(buttonStatus, "buttonStatus");
        this.a = choiceViewData;
        this.b = buttonStatus;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof a)) {
            return false;
        }
        a aVar = (a) obj;
        return Intrinsics.b(this.a, aVar.a) && this.b == aVar.b;
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "ChoiceButtonData(choiceViewData=" + this.a + ", buttonStatus=" + this.b + ")";
    }
}

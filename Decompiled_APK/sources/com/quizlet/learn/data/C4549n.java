package com.quizlet.learn.data;

import com.quizlet.features.infra.models.studymodeshared.StudyableModelData;
import com.quizlet.studiablemodels.AssistantCheckpointProgressState;
import com.quizlet.studiablemodels.StudiableMeteringData;
import com.quizlet.studiablemodels.StudiableTaskProgress;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.learn.data.n, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4549n extends AbstractC4550o {
    public final StudyableModelData a;
    public final StudiableTaskProgress b;
    public final StudiableMeteringData c;
    public final AssistantCheckpointProgressState d;

    public C4549n(StudyableModelData studyableModelData, StudiableTaskProgress studiableTaskProgress, StudiableMeteringData studiableMeteringData, AssistantCheckpointProgressState progressState) {
        Intrinsics.checkNotNullParameter(studyableModelData, "studyableModelData");
        Intrinsics.checkNotNullParameter(progressState, "progressState");
        this.a = studyableModelData;
        this.b = studiableTaskProgress;
        this.c = studiableMeteringData;
        this.d = progressState;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C4549n)) {
            return false;
        }
        C4549n c4549n = (C4549n) obj;
        return Intrinsics.b(this.a, c4549n.a) && Intrinsics.b(this.b, c4549n.b) && Intrinsics.b(this.c, c4549n.c) && this.d == c4549n.d;
    }

    public final int hashCode() {
        int iHashCode = this.a.hashCode() * 31;
        StudiableTaskProgress studiableTaskProgress = this.b;
        int iHashCode2 = (iHashCode + (studiableTaskProgress == null ? 0 : studiableTaskProgress.hashCode())) * 31;
        StudiableMeteringData studiableMeteringData = this.c;
        return this.d.hashCode() + ((iHashCode2 + (studiableMeteringData != null ? studiableMeteringData.hashCode() : 0)) * 31);
    }

    public final String toString() {
        return "SimplifiedLearnEnding(studyableModelData=" + this.a + ", currentTaskProgress=" + this.b + ", meteringData=" + this.c + ", progressState=" + this.d + ")";
    }
}

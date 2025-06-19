package com.quizlet.learn.data;

import androidx.compose.animation.d0;
import com.quizlet.features.infra.basestudy.data.models.logging.StudyEventLogData;
import com.quizlet.features.infra.models.studymodeshared.StudyableModelData;
import com.quizlet.generated.enums.A1;
import com.quizlet.studiablemodels.AssistantCheckpointProgressState;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.learn.data.m, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4548m extends AbstractC4550o {
    public final AssistantCheckpointProgressState a;
    public final double b;
    public final StudyEventLogData c;
    public final A1 d;
    public final StudyableModelData e;

    public C4548m(AssistantCheckpointProgressState progressState, double d, StudyEventLogData studyEventLogData, A1 studyModeType, StudyableModelData studyableModelData) {
        Intrinsics.checkNotNullParameter(progressState, "progressState");
        Intrinsics.checkNotNullParameter(studyEventLogData, "studyEventLogData");
        Intrinsics.checkNotNullParameter(studyModeType, "studyModeType");
        Intrinsics.checkNotNullParameter(studyableModelData, "studyableModelData");
        this.a = progressState;
        this.b = d;
        this.c = studyEventLogData;
        this.d = studyModeType;
        this.e = studyableModelData;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C4548m)) {
            return false;
        }
        C4548m c4548m = (C4548m) obj;
        return this.a == c4548m.a && Double.compare(this.b, c4548m.b) == 0 && Intrinsics.b(this.c, c4548m.c) && this.d == c4548m.d && Intrinsics.b(this.e, c4548m.e);
    }

    public final int hashCode() {
        return this.e.hashCode() + ((this.d.hashCode() + ((this.c.hashCode() + d0.a(this.b, this.a.hashCode() * 31, 31)) * 31)) * 31);
    }

    public final String toString() {
        return "ResultsCheckpoint(progressState=" + this.a + ", progressPercent=" + this.b + ", studyEventLogData=" + this.c + ", studyModeType=" + this.d + ", studyableModelData=" + this.e + ")";
    }
}

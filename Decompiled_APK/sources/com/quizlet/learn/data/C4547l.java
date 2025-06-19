package com.quizlet.learn.data;

import com.quizlet.features.infra.basestudy.data.models.logging.StudyEventLogData;
import com.quizlet.features.infra.models.studymodeshared.StudyableModelData;
import com.quizlet.generated.enums.A1;
import com.quizlet.studiablemodels.StudiableCheckpoint;
import com.quizlet.studiablemodels.StudiableTotalProgress;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.learn.data.l, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4547l extends AbstractC4550o {
    public final StudiableCheckpoint a;
    public final StudiableTotalProgress b;
    public final StudyEventLogData c;
    public final A1 d;
    public final StudyableModelData e;
    public final String f;

    public C4547l(StudiableCheckpoint checkpoint, StudiableTotalProgress totalProgress, StudyEventLogData studyEventLogData, A1 studyModeType, StudyableModelData studyableModelData, String studyableTitle) {
        Intrinsics.checkNotNullParameter(checkpoint, "checkpoint");
        Intrinsics.checkNotNullParameter(totalProgress, "totalProgress");
        Intrinsics.checkNotNullParameter(studyEventLogData, "studyEventLogData");
        Intrinsics.checkNotNullParameter(studyModeType, "studyModeType");
        Intrinsics.checkNotNullParameter(studyableModelData, "studyableModelData");
        Intrinsics.checkNotNullParameter(studyableTitle, "studyableTitle");
        this.a = checkpoint;
        this.b = totalProgress;
        this.c = studyEventLogData;
        this.d = studyModeType;
        this.e = studyableModelData;
        this.f = studyableTitle;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C4547l)) {
            return false;
        }
        C4547l c4547l = (C4547l) obj;
        return Intrinsics.b(this.a, c4547l.a) && Intrinsics.b(this.b, c4547l.b) && Intrinsics.b(this.c, c4547l.c) && this.d == c4547l.d && Intrinsics.b(this.e, c4547l.e) && Intrinsics.b(this.f, c4547l.f);
    }

    public final int hashCode() {
        return this.f.hashCode() + ((this.e.hashCode() + ((this.d.hashCode() + ((this.c.hashCode() + ((this.b.hashCode() + (this.a.hashCode() * 31)) * 31)) * 31)) * 31)) * 31);
    }

    public final String toString() {
        return "NewRoundCheckpoint(checkpoint=" + this.a + ", totalProgress=" + this.b + ", studyEventLogData=" + this.c + ", studyModeType=" + this.d + ", studyableModelData=" + this.e + ", studyableTitle=" + this.f + ")";
    }
}

package com.quizlet.quizletandroid.ui.studymodes.testmode.models;

import com.quizlet.data.model.InterfaceC4176w0;
import com.quizlet.features.infra.basestudy.data.models.logging.StudyEventLogData;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class s implements x {
    public final StudyEventLogData a;
    public final InterfaceC4176w0 b;

    public s(StudyEventLogData studyEventLogData, InterfaceC4176w0 meteredEvent) {
        Intrinsics.checkNotNullParameter(studyEventLogData, "studyEventLogData");
        Intrinsics.checkNotNullParameter(meteredEvent, "meteredEvent");
        this.a = studyEventLogData;
        this.b = meteredEvent;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof s)) {
            return false;
        }
        s sVar = (s) obj;
        return Intrinsics.b(this.a, sVar.a) && Intrinsics.b(this.b, sVar.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "StartViewState(studyEventLogData=" + this.a + ", meteredEvent=" + this.b + ")";
    }
}

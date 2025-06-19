package com.quizlet.features.infra.basestudy.data.models;

import androidx.compose.animation.d0;
import com.quizlet.data.model.InterfaceC4176w0;
import com.quizlet.data.model.StudySet;
import com.quizlet.features.infra.models.studymodeshared.StudyableModelData;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class u implements l {
    public final StudyableModelData.StudySet a;
    public final long b;
    public final boolean c;
    public final InterfaceC4176w0 d;
    public final InterfaceC4176w0 e;

    public u(StudySet studySet, boolean z, InterfaceC4176w0 testMeteredEvent, InterfaceC4176w0 learnMeteredEvent) {
        Intrinsics.checkNotNullParameter(studySet, "studySet");
        Intrinsics.checkNotNullParameter(testMeteredEvent, "testMeteredEvent");
        Intrinsics.checkNotNullParameter(learnMeteredEvent, "learnMeteredEvent");
        StudyableModelData.StudySet studyableModelData = new StudyableModelData.StudySet(studySet.a);
        Intrinsics.checkNotNullParameter(studyableModelData, "studyableModelData");
        Intrinsics.checkNotNullParameter(testMeteredEvent, "testMeteredEvent");
        Intrinsics.checkNotNullParameter(learnMeteredEvent, "learnMeteredEvent");
        this.a = studyableModelData;
        this.b = studySet.x;
        this.c = z;
        this.d = testMeteredEvent;
        this.e = learnMeteredEvent;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof u)) {
            return false;
        }
        u uVar = (u) obj;
        uVar.getClass();
        return this.a.equals(uVar.a) && this.b == uVar.b && this.c == uVar.c && Intrinsics.b(this.d, uVar.d) && Intrinsics.b(this.e, uVar.e);
    }

    public final int hashCode() {
        return this.e.hashCode() + ((this.d.hashCode() + d0.g(d0.d(d0.d(Integer.hashCode(1) * 31, 31, this.a.a), 31, this.b), 31, this.c)) * 31);
    }

    public final String toString() {
        return "StartTestMode(navigationSource=1, studyableModelData=" + this.a + ", localSetId=" + this.b + ", selectedTermsOnly=" + this.c + ", testMeteredEvent=" + this.d + ", learnMeteredEvent=" + this.e + ")";
    }
}

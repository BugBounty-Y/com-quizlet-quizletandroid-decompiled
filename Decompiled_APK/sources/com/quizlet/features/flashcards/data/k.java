package com.quizlet.features.flashcards.data;

import androidx.compose.animation.d0;
import com.quizlet.data.model.InterfaceC4176w0;
import com.quizlet.features.infra.models.studymodeshared.StudyableModelData;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class k extends l {
    public final int a;
    public final StudyableModelData b;
    public final long c;
    public final boolean d;
    public final InterfaceC4176w0 e;
    public final InterfaceC4176w0 f;

    public k(int i, StudyableModelData studyableModelData, long j, boolean z, InterfaceC4176w0 learnMeteredEvent, InterfaceC4176w0 testMeteredEvent) {
        Intrinsics.checkNotNullParameter(studyableModelData, "studyableModelData");
        Intrinsics.checkNotNullParameter(learnMeteredEvent, "learnMeteredEvent");
        Intrinsics.checkNotNullParameter(testMeteredEvent, "testMeteredEvent");
        this.a = i;
        this.b = studyableModelData;
        this.c = j;
        this.d = z;
        this.e = learnMeteredEvent;
        this.f = testMeteredEvent;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof k)) {
            return false;
        }
        k kVar = (k) obj;
        return this.a == kVar.a && Intrinsics.b(this.b, kVar.b) && this.c == kVar.c && this.d == kVar.d && Intrinsics.b(this.e, kVar.e) && Intrinsics.b(this.f, kVar.f);
    }

    public final int hashCode() {
        return this.f.hashCode() + ((this.e.hashCode() + d0.g(d0.d((this.b.hashCode() + (Integer.hashCode(this.a) * 31)) * 31, 31, this.c), 31, this.d)) * 31);
    }

    public final String toString() {
        return "Test(navigationSource=" + this.a + ", studyableModelData=" + this.b + ", localSetId=" + this.c + ", selectedTermsOnly=" + this.d + ", learnMeteredEvent=" + this.e + ", testMeteredEvent=" + this.f + ")";
    }
}

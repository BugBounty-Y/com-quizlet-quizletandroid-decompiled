package com.quizlet.learn.data;

import androidx.compose.animation.d0;
import com.quizlet.data.model.InterfaceC4176w0;
import com.quizlet.features.infra.models.studymodeshared.StudyableModelData;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class F extends N {
    public final int a;
    public final StudyableModelData b;
    public final long c;
    public final boolean d;
    public final InterfaceC4176w0 e;
    public final InterfaceC4176w0 f;

    public F(int i, StudyableModelData studyableModelData, long j, boolean z, InterfaceC4176w0 learnMeteredEvent, InterfaceC4176w0 testMeteredEvent) {
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
        if (!(obj instanceof F)) {
            return false;
        }
        F f = (F) obj;
        return this.a == f.a && Intrinsics.b(this.b, f.b) && this.c == f.c && this.d == f.d && Intrinsics.b(this.e, f.e) && Intrinsics.b(this.f, f.f);
    }

    public final int hashCode() {
        return this.f.hashCode() + ((this.e.hashCode() + d0.g(d0.d((this.b.hashCode() + (Integer.hashCode(this.a) * 31)) * 31, 31, this.c), 31, this.d)) * 31);
    }

    public final String toString() {
        return "GoToTest(navigationSource=" + this.a + ", studyableModelData=" + this.b + ", localSetId=" + this.c + ", selectedTermsOnly=" + this.d + ", learnMeteredEvent=" + this.e + ", testMeteredEvent=" + this.f + ")";
    }
}

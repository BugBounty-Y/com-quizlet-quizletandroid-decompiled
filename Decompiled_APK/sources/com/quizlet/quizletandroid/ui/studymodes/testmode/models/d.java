package com.quizlet.quizletandroid.ui.studymodes.testmode.models;

import androidx.compose.animation.d0;
import com.quizlet.data.model.InterfaceC4176w0;
import com.quizlet.features.infra.models.studymodeshared.StudyableModelData;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class d implements v {
    public final StudyableModelData a;
    public final long b;
    public final String c;
    public final boolean d;
    public final InterfaceC4176w0 e;
    public final List f;
    public final boolean g;

    public d(StudyableModelData studyableModelData, long j, String setTitle, boolean z, InterfaceC4176w0 meteredEvent, List missedTermIds, boolean z2) {
        Intrinsics.checkNotNullParameter(studyableModelData, "studyableModelData");
        Intrinsics.checkNotNullParameter(setTitle, "setTitle");
        Intrinsics.checkNotNullParameter(meteredEvent, "meteredEvent");
        Intrinsics.checkNotNullParameter(missedTermIds, "missedTermIds");
        this.a = studyableModelData;
        this.b = j;
        this.c = setTitle;
        this.d = z;
        this.e = meteredEvent;
        this.f = missedTermIds;
        this.g = z2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof d)) {
            return false;
        }
        d dVar = (d) obj;
        dVar.getClass();
        return this.a.equals(dVar.a) && this.b == dVar.b && this.c.equals(dVar.c) && this.d == dVar.d && Intrinsics.b(this.e, dVar.e) && Intrinsics.b(this.f, dVar.f) && this.g == dVar.g;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.g) + d0.f((this.e.hashCode() + d0.g(d0.e(d0.d((this.a.hashCode() + (Integer.hashCode(0) * 31)) * 31, 31, this.b), 31, this.c), 31, this.d)) * 31, 31, this.f);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("GoToLearn(navigationSource=0, studyableModelData=");
        sb.append(this.a);
        sb.append(", localSetId=");
        sb.append(this.b);
        sb.append(", setTitle=");
        sb.append(this.c);
        sb.append(", selectedTermsOnly=");
        sb.append(this.d);
        sb.append(", meteredEvent=");
        sb.append(this.e);
        sb.append(", missedTermIds=");
        sb.append(this.f);
        sb.append(", showOnboarding=");
        return android.support.v4.media.session.a.o(")", sb, this.g);
    }
}

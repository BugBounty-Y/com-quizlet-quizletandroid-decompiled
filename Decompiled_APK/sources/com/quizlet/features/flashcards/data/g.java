package com.quizlet.features.flashcards.data;

import androidx.compose.animation.d0;
import com.quizlet.data.model.InterfaceC4176w0;
import com.quizlet.features.infra.models.studymodeshared.StudyableModelData;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class g extends l {
    public final int a;
    public final StudyableModelData b;
    public final long c;
    public final String d;
    public final boolean e;
    public final InterfaceC4176w0 f;
    public final boolean g;

    public g(int i, StudyableModelData studyableModelData, long j, String setTitle, boolean z, InterfaceC4176w0 meteredEvent, boolean z2) {
        Intrinsics.checkNotNullParameter(studyableModelData, "studyableModelData");
        Intrinsics.checkNotNullParameter(setTitle, "setTitle");
        Intrinsics.checkNotNullParameter(meteredEvent, "meteredEvent");
        this.a = i;
        this.b = studyableModelData;
        this.c = j;
        this.d = setTitle;
        this.e = z;
        this.f = meteredEvent;
        this.g = z2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof g)) {
            return false;
        }
        g gVar = (g) obj;
        return this.a == gVar.a && Intrinsics.b(this.b, gVar.b) && this.c == gVar.c && Intrinsics.b(this.d, gVar.d) && this.e == gVar.e && Intrinsics.b(this.f, gVar.f) && this.g == gVar.g;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.g) + ((this.f.hashCode() + d0.g(d0.e(d0.d((this.b.hashCode() + (Integer.hashCode(this.a) * 31)) * 31, 31, this.c), 31, this.d), 31, this.e)) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("Learn(navigationSource=");
        sb.append(this.a);
        sb.append(", studyableModelData=");
        sb.append(this.b);
        sb.append(", localSetId=");
        sb.append(this.c);
        sb.append(", setTitle=");
        sb.append(this.d);
        sb.append(", selectedTermsOnly=");
        sb.append(this.e);
        sb.append(", meteredEvent=");
        sb.append(this.f);
        sb.append(", showOnboarding=");
        return android.support.v4.media.session.a.o(")", sb, this.g);
    }
}

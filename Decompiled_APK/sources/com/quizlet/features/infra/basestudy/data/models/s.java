package com.quizlet.features.infra.basestudy.data.models;

import androidx.compose.animation.d0;
import com.quizlet.data.model.InterfaceC4176w0;
import com.quizlet.data.model.StudySet;
import com.quizlet.features.infra.models.studymodeshared.StudyableModelData;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class s implements k {
    public final StudyableModelData.StudySet a;
    public final String b;
    public final long c;
    public final boolean d;
    public final List e;
    public final InterfaceC4176w0 f;
    public final boolean g;

    public s(StudySet studySet, boolean z, List list, InterfaceC4176w0 meteredEvent, boolean z2) {
        Intrinsics.checkNotNullParameter(studySet, "studySet");
        Intrinsics.checkNotNullParameter(meteredEvent, "meteredEvent");
        StudyableModelData.StudySet studyableModelData = new StudyableModelData.StudySet(studySet.a);
        Intrinsics.checkNotNullParameter(studyableModelData, "studyableModelData");
        String setTitle = studySet.h;
        Intrinsics.checkNotNullParameter(setTitle, "setTitle");
        Intrinsics.checkNotNullParameter(meteredEvent, "meteredEvent");
        this.a = studyableModelData;
        this.b = setTitle;
        this.c = studySet.x;
        this.d = z;
        this.e = list;
        this.f = meteredEvent;
        this.g = z2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof s)) {
            return false;
        }
        s sVar = (s) obj;
        sVar.getClass();
        return this.a.equals(sVar.a) && Intrinsics.b(this.b, sVar.b) && this.c == sVar.c && this.d == sVar.d && Intrinsics.b(this.e, sVar.e) && Intrinsics.b(this.f, sVar.f) && this.g == sVar.g;
    }

    public final int hashCode() {
        int iG = d0.g(d0.d(d0.e(d0.d(Integer.hashCode(1) * 31, 31, this.a.a), 31, this.b), 31, this.c), 31, this.d);
        List list = this.e;
        return Boolean.hashCode(this.g) + ((this.f.hashCode() + d0.b(0, (iG + (list == null ? 0 : list.hashCode())) * 31, 31)) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("StartLearnMode(navigationSource=1, studyableModelData=");
        sb.append(this.a);
        sb.append(", setTitle=");
        sb.append(this.b);
        sb.append(", localSetId=");
        sb.append(this.c);
        sb.append(", selectedTermsOnly=");
        sb.append(this.d);
        sb.append(", termIdsToShowOnly=");
        sb.append(this.e);
        sb.append(", assitantBehavior=0, meteredEvent=");
        sb.append(this.f);
        sb.append(", showOnboarding=");
        return android.support.v4.media.session.a.o(")", sb, this.g);
    }
}

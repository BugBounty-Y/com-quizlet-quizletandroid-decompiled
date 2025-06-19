package com.quizlet.features.infra.basestudy.data.models;

import androidx.compose.animation.d0;
import com.quizlet.data.model.StudySet;
import com.quizlet.features.infra.models.studymodeshared.StudyableModelData;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class t implements w {
    public final StudyableModelData.StudySet a;
    public final long b;
    public final boolean c;
    public final String d;

    public t(StudySet studySet, boolean z) {
        Intrinsics.checkNotNullParameter(studySet, "studySet");
        StudyableModelData.StudySet studyableModelData = new StudyableModelData.StudySet(studySet.a);
        Intrinsics.checkNotNullParameter(studyableModelData, "studyableModelData");
        this.a = studyableModelData;
        this.b = studySet.x;
        this.c = z;
        this.d = studySet.t;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof t)) {
            return false;
        }
        t tVar = (t) obj;
        tVar.getClass();
        return this.a.equals(tVar.a) && this.b == tVar.b && this.c == tVar.c && Intrinsics.b(this.d, tVar.d);
    }

    public final int hashCode() {
        int iG = d0.g(d0.d(d0.d(Integer.hashCode(1) * 31, 31, this.a.a), 31, this.b), 31, this.c);
        String str = this.d;
        return iG + (str == null ? 0 : str.hashCode());
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("StartMatchMode(navigationSource=1, studyableModelData=");
        sb.append(this.a);
        sb.append(", localSetId=");
        sb.append(this.b);
        sb.append(", selectedTermsOnly=");
        sb.append(this.c);
        sb.append(", webUrl=");
        return android.support.v4.media.session.a.t(sb, this.d, ")");
    }
}

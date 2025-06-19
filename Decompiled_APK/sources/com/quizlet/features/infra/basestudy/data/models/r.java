package com.quizlet.features.infra.basestudy.data.models;

import androidx.compose.animation.d0;
import com.quizlet.features.infra.models.studymodeshared.StudyableModelData;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class r implements w {
    public final int a;
    public final StudyableModelData b;
    public final long c;
    public final String d;
    public final boolean e;
    public final String f;

    public r(int i, long j, StudyableModelData studyableModelData, String setTitle, String str, boolean z) {
        Intrinsics.checkNotNullParameter(studyableModelData, "studyableModelData");
        Intrinsics.checkNotNullParameter(setTitle, "setTitle");
        this.a = i;
        this.b = studyableModelData;
        this.c = j;
        this.d = setTitle;
        this.e = z;
        this.f = str;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof r)) {
            return false;
        }
        r rVar = (r) obj;
        return this.a == rVar.a && Intrinsics.b(this.b, rVar.b) && this.c == rVar.c && Intrinsics.b(this.d, rVar.d) && this.e == rVar.e && Intrinsics.b(this.f, rVar.f);
    }

    public final int hashCode() {
        int iG = d0.g(d0.e(d0.d((this.b.hashCode() + (Integer.hashCode(this.a) * 31)) * 31, 31, this.c), 31, this.d), 31, this.e);
        String str = this.f;
        return iG + (str == null ? 0 : str.hashCode());
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("StartCardsMode(navigationSource=");
        sb.append(this.a);
        sb.append(", studyableModelData=");
        sb.append(this.b);
        sb.append(", localSetId=");
        sb.append(this.c);
        sb.append(", setTitle=");
        sb.append(this.d);
        sb.append(", selectedTermsOnly=");
        sb.append(this.e);
        sb.append(", webUrl=");
        return android.support.v4.media.session.a.t(sb, this.f, ")");
    }
}

package com.quizlet.features.infra.basestudy.data.models;

import androidx.compose.animation.d0;
import com.quizlet.features.infra.models.studymodeshared.StudyableModelData;
import com.quizlet.generated.enums.A1;
import java.util.ArrayList;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class x {
    public final StudyableModelData a;
    public final long b;
    public final boolean c;
    public final String d;
    public final int e;
    public final ArrayList f;
    public final A1 g;
    public final Boolean h;

    public x(StudyableModelData studyableModelData, long j, boolean z, String screenName, int i, ArrayList arrayList, A1 studyModeType, Boolean bool) {
        Intrinsics.checkNotNullParameter(studyableModelData, "studyableModelData");
        Intrinsics.checkNotNullParameter(screenName, "screenName");
        Intrinsics.checkNotNullParameter(studyModeType, "studyModeType");
        this.a = studyableModelData;
        this.b = j;
        this.c = z;
        this.d = screenName;
        this.e = i;
        this.f = arrayList;
        this.g = studyModeType;
        this.h = bool;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof x)) {
            return false;
        }
        x xVar = (x) obj;
        return Intrinsics.b(this.a, xVar.a) && this.b == xVar.b && this.c == xVar.c && Intrinsics.b(this.d, xVar.d) && this.e == xVar.e && Intrinsics.b(this.f, xVar.f) && this.g == xVar.g && Intrinsics.b(this.h, xVar.h);
    }

    public final int hashCode() {
        int iB = d0.b(this.e, d0.e(d0.g(d0.d(this.a.hashCode() * 31, 31, this.b), 31, this.c), 31, this.d), 31);
        ArrayList arrayList = this.f;
        int iHashCode = (this.g.hashCode() + ((iB + (arrayList == null ? 0 : arrayList.hashCode())) * 31)) * 31;
        Boolean bool = this.h;
        return iHashCode + (bool != null ? bool.hashCode() : 0);
    }

    public final String toString() {
        return "StudyModeConfiguration(studyableModelData=" + this.a + ", studyableModelLocalId=" + this.b + ", selectedTermsOnly=" + this.c + ", screenName=" + this.d + ", navigationSource=" + this.e + ", termIdsToFilterBy=" + this.f + ", studyModeType=" + this.g + ", startsInSrsReview=" + this.h + ")";
    }
}

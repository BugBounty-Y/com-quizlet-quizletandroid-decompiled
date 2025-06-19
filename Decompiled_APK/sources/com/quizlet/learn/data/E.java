package com.quizlet.learn.data;

import androidx.compose.animation.d0;
import com.quizlet.features.infra.models.studymodeshared.StudyableModelData;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class E extends N {
    public final String a;
    public final StudyableModelData b;
    public final long c;
    public final boolean d;
    public final String e;
    public final int f;
    public final boolean g;

    public E(String studySessionId, StudyableModelData studyableModelData, long j, boolean z, String screenName, int i, boolean z2) {
        Intrinsics.checkNotNullParameter(studySessionId, "studySessionId");
        Intrinsics.checkNotNullParameter(studyableModelData, "studyableModelData");
        Intrinsics.checkNotNullParameter(screenName, "screenName");
        this.a = studySessionId;
        this.b = studyableModelData;
        this.c = j;
        this.d = z;
        this.e = screenName;
        this.f = i;
        this.g = z2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof E)) {
            return false;
        }
        E e = (E) obj;
        return Intrinsics.b(this.a, e.a) && Intrinsics.b(this.b, e.b) && this.c == e.c && this.d == e.d && Intrinsics.b(this.e, e.e) && this.f == e.f && this.g == e.g;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.g) + d0.b(this.f, d0.e(d0.g(d0.d((this.b.hashCode() + (this.a.hashCode() * 31)) * 31, 31, this.c), 31, this.d), 31, this.e), 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("GoToSettingsPage(studySessionId=");
        sb.append(this.a);
        sb.append(", studyableModelData=");
        sb.append(this.b);
        sb.append(", studyableModelLocalId=");
        sb.append(this.c);
        sb.append(", selectedTermsOnly=");
        sb.append(this.d);
        sb.append(", screenName=");
        sb.append(this.e);
        sb.append(", navigationSource=");
        sb.append(this.f);
        sb.append(", useRefreshedSettings=");
        return android.support.v4.media.session.a.o(")", sb, this.g);
    }
}

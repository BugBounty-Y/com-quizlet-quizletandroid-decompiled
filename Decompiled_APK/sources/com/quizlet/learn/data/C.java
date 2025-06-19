package com.quizlet.learn.data;

import androidx.compose.animation.d0;
import com.quizlet.features.infra.models.studymodeshared.StudyableModelData;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class C extends N {
    public final int a;
    public final StudyableModelData b;
    public final long c;
    public final String d;
    public final boolean e;

    public C(int i, StudyableModelData studyableModelData, long j, String setTitle, boolean z) {
        Intrinsics.checkNotNullParameter(studyableModelData, "studyableModelData");
        Intrinsics.checkNotNullParameter(setTitle, "setTitle");
        this.a = i;
        this.b = studyableModelData;
        this.c = j;
        this.d = setTitle;
        this.e = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C)) {
            return false;
        }
        C c = (C) obj;
        return this.a == c.a && Intrinsics.b(this.b, c.b) && this.c == c.c && Intrinsics.b(this.d, c.d) && this.e == c.e;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.e) + d0.e(d0.d((this.b.hashCode() + (Integer.hashCode(this.a) * 31)) * 31, 31, this.c), 31, this.d);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("GoToFlashcards(navigationSource=");
        sb.append(this.a);
        sb.append(", studyableModelData=");
        sb.append(this.b);
        sb.append(", localSetId=");
        sb.append(this.c);
        sb.append(", setTitle=");
        sb.append(this.d);
        sb.append(", selectedTermsOnly=");
        return android.support.v4.media.session.a.o(")", sb, this.e);
    }
}

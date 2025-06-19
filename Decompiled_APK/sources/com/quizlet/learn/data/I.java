package com.quizlet.learn.data;

import androidx.compose.animation.d0;
import com.quizlet.generated.enums.G1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class I extends N {
    public final long a;
    public final String b;
    public final long c;
    public final G1 d;
    public final boolean e;

    public I(long j, String setTitle, long j2, G1 studyableType, boolean z) {
        Intrinsics.checkNotNullParameter(setTitle, "setTitle");
        Intrinsics.checkNotNullParameter(studyableType, "studyableType");
        this.a = j;
        this.b = setTitle;
        this.c = j2;
        this.d = studyableType;
        this.e = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof I)) {
            return false;
        }
        I i = (I) obj;
        i.getClass();
        return this.a == i.a && Intrinsics.b(this.b, i.b) && this.c == i.c && this.d == i.d && this.e == i.e;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.e) + ((this.d.hashCode() + d0.d(d0.e(d0.d(Integer.hashCode(0) * 31, 31, this.a), 31, this.b), 31, this.c)) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("GoToWriteMode(navigationSource=0, setId=");
        sb.append(this.a);
        sb.append(", setTitle=");
        sb.append(this.b);
        sb.append(", localSetId=");
        sb.append(this.c);
        sb.append(", studyableType=");
        sb.append(this.d);
        sb.append(", selectedTermsOnly=");
        return android.support.v4.media.session.a.o(")", sb, this.e);
    }
}

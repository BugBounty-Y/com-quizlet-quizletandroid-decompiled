package com.quizlet.learn.data.onboarding;

import androidx.compose.animation.d0;
import com.quizlet.generated.enums.G1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class x extends B {
    public final int a;
    public final long b;
    public final String c;
    public final long d;
    public final G1 e;
    public final boolean f;

    public x(int i, long j, String setTitle, long j2, G1 studyableType, boolean z) {
        Intrinsics.checkNotNullParameter(setTitle, "setTitle");
        Intrinsics.checkNotNullParameter(studyableType, "studyableType");
        this.a = i;
        this.b = j;
        this.c = setTitle;
        this.d = j2;
        this.e = studyableType;
        this.f = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof x)) {
            return false;
        }
        x xVar = (x) obj;
        return this.a == xVar.a && this.b == xVar.b && Intrinsics.b(this.c, xVar.c) && this.d == xVar.d && this.e == xVar.e && this.f == xVar.f;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.f) + ((this.e.hashCode() + d0.d(d0.e(d0.d(Integer.hashCode(this.a) * 31, 31, this.b), 31, this.c), 31, this.d)) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("GoToWrite(navigationSource=");
        sb.append(this.a);
        sb.append(", setId=");
        sb.append(this.b);
        sb.append(", setTitle=");
        sb.append(this.c);
        sb.append(", localSetId=");
        sb.append(this.d);
        sb.append(", studyableType=");
        sb.append(this.e);
        sb.append(", selectedTermsOnly=");
        return android.support.v4.media.session.a.o(")", sb, this.f);
    }
}

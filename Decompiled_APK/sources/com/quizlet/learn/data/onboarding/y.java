package com.quizlet.learn.data.onboarding;

import androidx.compose.animation.d0;
import com.quizlet.data.model.InterfaceC4176w0;
import com.quizlet.generated.enums.G1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class y extends B {
    public final int a;
    public final long b;
    public final String c;
    public final long d;
    public final G1 e;
    public final boolean f;
    public final InterfaceC4176w0 g;

    public y(int i, long j, String setTitle, long j2, G1 studyableType, boolean z, InterfaceC4176w0 meteredEvent) {
        Intrinsics.checkNotNullParameter(setTitle, "setTitle");
        Intrinsics.checkNotNullParameter(studyableType, "studyableType");
        Intrinsics.checkNotNullParameter(meteredEvent, "meteredEvent");
        this.a = i;
        this.b = j;
        this.c = setTitle;
        this.d = j2;
        this.e = studyableType;
        this.f = z;
        this.g = meteredEvent;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof y)) {
            return false;
        }
        y yVar = (y) obj;
        return this.a == yVar.a && this.b == yVar.b && Intrinsics.b(this.c, yVar.c) && this.d == yVar.d && this.e == yVar.e && this.f == yVar.f && Intrinsics.b(this.g, yVar.g);
    }

    public final int hashCode() {
        return this.g.hashCode() + d0.b(1, d0.g((this.e.hashCode() + d0.d(d0.e(d0.d(Integer.hashCode(this.a) * 31, 31, this.b), 31, this.c), 31, this.d)) * 31, 31, this.f), 31);
    }

    public final String toString() {
        return "GoToWriteAsLearn(navigationSource=" + this.a + ", setId=" + this.b + ", setTitle=" + this.c + ", localSetId=" + this.d + ", studyableType=" + this.e + ", selectedTermsOnly=" + this.f + ", assitantBehavior=1, meteredEvent=" + this.g + ")";
    }
}

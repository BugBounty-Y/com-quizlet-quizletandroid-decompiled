package com.quizlet.learn.data;

import androidx.compose.animation.d0;
import com.quizlet.data.model.InterfaceC4176w0;
import com.quizlet.generated.enums.G1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class H extends N {
    public final long a;
    public final String b;
    public final long c;
    public final G1 d;
    public final boolean e;
    public final InterfaceC4176w0 f;

    public H(long j, String setTitle, long j2, G1 studyableType, boolean z, InterfaceC4176w0 meteredEvent) {
        Intrinsics.checkNotNullParameter(setTitle, "setTitle");
        Intrinsics.checkNotNullParameter(studyableType, "studyableType");
        Intrinsics.checkNotNullParameter(meteredEvent, "meteredEvent");
        this.a = j;
        this.b = setTitle;
        this.c = j2;
        this.d = studyableType;
        this.e = z;
        this.f = meteredEvent;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof H)) {
            return false;
        }
        H h = (H) obj;
        h.getClass();
        return this.a == h.a && Intrinsics.b(this.b, h.b) && this.c == h.c && this.d == h.d && this.e == h.e && Intrinsics.b(this.f, h.f);
    }

    public final int hashCode() {
        return this.f.hashCode() + d0.b(1, d0.g((this.d.hashCode() + d0.d(d0.e(d0.d(Integer.hashCode(0) * 31, 31, this.a), 31, this.b), 31, this.c)) * 31, 31, this.e), 31);
    }

    public final String toString() {
        return "GoToWriteAsLearnMode(navigationSource=0, setId=" + this.a + ", setTitle=" + this.b + ", localSetId=" + this.c + ", studyableType=" + this.d + ", selectedTermsOnly=" + this.e + ", assitantBehavior=1, meteredEvent=" + this.f + ")";
    }
}

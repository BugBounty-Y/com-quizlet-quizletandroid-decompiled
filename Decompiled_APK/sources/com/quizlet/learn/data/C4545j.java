package com.quizlet.learn.data;

import androidx.compose.animation.d0;
import com.quizlet.studiablemodels.StudiableMeteringData;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.learn.data.j, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4545j extends t {
    public final long a;
    public final String b;
    public final StudiableMeteringData c;

    public C4545j(long j, String studySessionId, StudiableMeteringData studiableMeteringData) {
        Intrinsics.checkNotNullParameter(studySessionId, "studySessionId");
        this.a = j;
        this.b = studySessionId;
        this.c = studiableMeteringData;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C4545j)) {
            return false;
        }
        C4545j c4545j = (C4545j) obj;
        return this.a == c4545j.a && Intrinsics.b(this.b, c4545j.b) && Intrinsics.b(this.c, c4545j.c);
    }

    public final int hashCode() {
        int iE = d0.e(Long.hashCode(this.a) * 31, 31, this.b);
        StudiableMeteringData studiableMeteringData = this.c;
        return iE + (studiableMeteringData == null ? 0 : studiableMeteringData.hashCode());
    }

    public final String toString() {
        return "MeteringPaywallState(setId=" + this.a + ", studySessionId=" + this.b + ", meteringData=" + this.c + ")";
    }
}

package com.quizlet.learn.data;

import com.quizlet.studiablemodels.StudiableMeteringData;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.learn.data.k, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4546k extends AbstractC4550o {
    public final LearnRoundSummaryData a;
    public final StudiableMeteringData b;
    public final boolean c;

    public C4546k(LearnRoundSummaryData roundSummaryData, StudiableMeteringData studiableMeteringData, boolean z) {
        Intrinsics.checkNotNullParameter(roundSummaryData, "roundSummaryData");
        this.a = roundSummaryData;
        this.b = studiableMeteringData;
        this.c = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C4546k)) {
            return false;
        }
        C4546k c4546k = (C4546k) obj;
        return this.a.equals(c4546k.a) && Intrinsics.b(this.b, c4546k.b) && this.c == c4546k.c;
    }

    public final int hashCode() {
        int iHashCode = this.a.hashCode() * 31;
        StudiableMeteringData studiableMeteringData = this.b;
        return Boolean.hashCode(this.c) + ((iHashCode + (studiableMeteringData == null ? 0 : studiableMeteringData.hashCode())) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("LearnRoundSummary(roundSummaryData=");
        sb.append(this.a);
        sb.append(", meteringData=");
        sb.append(this.b);
        sb.append(", isFocusedLearnResults=");
        return android.support.v4.media.session.a.o(")", sb, this.c);
    }
}

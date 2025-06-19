package com.quizlet.quizletandroid.ui.studymodes.testmode.models;

import androidx.compose.animation.d0;
import com.quizlet.studiablemodels.StudiableMeteringData;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class k implements x {
    public final long a;
    public final String b;
    public final StudiableMeteringData c;
    public final boolean d;

    public k(long j, String studySessionId, StudiableMeteringData meteringData, boolean z) {
        Intrinsics.checkNotNullParameter(studySessionId, "studySessionId");
        Intrinsics.checkNotNullParameter(meteringData, "meteringData");
        this.a = j;
        this.b = studySessionId;
        this.c = meteringData;
        this.d = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof k)) {
            return false;
        }
        k kVar = (k) obj;
        return this.a == kVar.a && Intrinsics.b(this.b, kVar.b) && this.c.equals(kVar.c) && this.d == kVar.d;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.d) + ((this.c.hashCode() + d0.e(Long.hashCode(this.a) * 31, 31, this.b)) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("PaywallViewState(setId=");
        sb.append(this.a);
        sb.append(", studySessionId=");
        sb.append(this.b);
        sb.append(", meteringData=");
        sb.append(this.c);
        sb.append(", launchedFromResults=");
        return android.support.v4.media.session.a.o(")", sb, this.d);
    }
}

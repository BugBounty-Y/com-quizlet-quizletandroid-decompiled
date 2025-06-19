package com.quizlet.quizletandroid.ui.studymodes.testmode.start;

import com.quizlet.studiablemodels.StudiableMeteringData;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class f extends h {
    public final StudiableMeteringData a;

    public f(StudiableMeteringData meteringData) {
        Intrinsics.checkNotNullParameter(meteringData, "meteringData");
        this.a = meteringData;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof f) && Intrinsics.b(this.a, ((f) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "ShowPaywall(meteringData=" + this.a + ")";
    }
}

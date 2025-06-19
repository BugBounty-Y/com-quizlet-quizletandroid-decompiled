package com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels;

import com.quizlet.studiablemodels.StudiableMeteringData;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.f, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4764f extends AbstractC4766h {
    public final StudiableMeteringData a;

    public C4764f(StudiableMeteringData meteringData) {
        Intrinsics.checkNotNullParameter(meteringData, "meteringData");
        this.a = meteringData;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof C4764f) && Intrinsics.b(this.a, ((C4764f) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "ShowPaywall(meteringData=" + this.a + ")";
    }
}

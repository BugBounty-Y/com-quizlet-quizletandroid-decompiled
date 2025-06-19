package com.quizlet.features.match.data;

import com.google.android.gms.internal.mlkit_vision_barcode.O6;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.features.match.data.f, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4350f extends AbstractC4352h {
    public final O6 a;

    public C4350f(O6 matchData) {
        Intrinsics.checkNotNullParameter(matchData, "matchData");
        this.a = matchData;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof C4350f) && Intrinsics.b(this.a, ((C4350f) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "Correct(matchData=" + this.a + ")";
    }
}

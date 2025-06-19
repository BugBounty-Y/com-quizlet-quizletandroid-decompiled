package com.quizlet.features.match.data;

import com.google.android.gms.internal.mlkit_vision_barcode.O6;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.features.match.data.g, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4351g extends AbstractC4352h {
    public final O6 a;

    public C4351g(O6 matchData) {
        Intrinsics.checkNotNullParameter(matchData, "matchData");
        this.a = matchData;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof C4351g) && Intrinsics.b(this.a, ((C4351g) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "Incorrect(matchData=" + this.a + ")";
    }
}

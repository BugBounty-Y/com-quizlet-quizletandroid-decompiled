package com.quizlet.features.flashcards.data;

import androidx.compose.animation.d0;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3146g0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class e {
    public final AbstractC3146g0 a;
    public final int b;
    public final int c;
    public final int d;
    public final int e;
    public final boolean f;
    public final int g;

    public e(AbstractC3146g0 stepData, int i, int i2, int i3, int i4, boolean z) {
        Intrinsics.checkNotNullParameter(stepData, "stepData");
        this.a = stepData;
        this.b = i;
        this.c = i2;
        this.d = i3;
        this.e = i4;
        this.f = z;
        this.g = i3 + i2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof e)) {
            return false;
        }
        e eVar = (e) obj;
        return Intrinsics.b(this.a, eVar.a) && this.b == eVar.b && this.c == eVar.c && this.d == eVar.d && this.e == eVar.e && this.f == eVar.f;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.f) + d0.b(this.e, d0.b(this.d, d0.b(this.c, d0.b(this.b, this.a.hashCode() * 31, 31), 31), 31), 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("FlashcardsEngineStep(stepData=");
        sb.append(this.a);
        sb.append(", numCardsInCycle=");
        sb.append(this.b);
        sb.append(", numCardsMarkedStillLearningInCycle=");
        sb.append(this.c);
        sb.append(", numCardsMarkedKnownInCycle=");
        sb.append(this.d);
        sb.append(", totalNumCards=");
        sb.append(this.e);
        sb.append(", canUndo=");
        return android.support.v4.media.session.a.o(")", sb, this.f);
    }
}

package com.quizlet.quizletandroid.ui.onboarding;

import com.google.android.gms.internal.mlkit_vision_document_scanner.B5;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class d {
    public final B5 a;
    public final b b;

    public d(B5 currentStep, b bVar) {
        Intrinsics.checkNotNullParameter(currentStep, "currentStep");
        this.a = currentStep;
        this.b = bVar;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof d)) {
            return false;
        }
        d dVar = (d) obj;
        return Intrinsics.b(this.a, dVar.a) && Intrinsics.b(this.b, dVar.b);
    }

    public final int hashCode() {
        int i;
        int iHashCode = this.a.hashCode() * 31;
        b bVar = this.b;
        if (bVar == null) {
            i = 0;
        } else {
            bVar.getClass();
            i = 241705747;
        }
        return iHashCode + i;
    }

    public final String toString() {
        return "State(currentStep=" + this.a + ", error=" + this.b + ")";
    }
}

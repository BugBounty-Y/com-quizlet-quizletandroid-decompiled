package com.quizlet.features.questiontypes.selfassessment.data;

import com.quizlet.features.infra.models.flashcards.f;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a implements c {
    public final f a;
    public final f b;

    public a(f frontData, f backData) {
        Intrinsics.checkNotNullParameter(frontData, "frontData");
        Intrinsics.checkNotNullParameter(backData, "backData");
        this.a = frontData;
        this.b = backData;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof a)) {
            return false;
        }
        a aVar = (a) obj;
        return Intrinsics.b(this.a, aVar.a) && Intrinsics.b(this.b, aVar.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "FlashcardViewState(frontData=" + this.a + ", backData=" + this.b + ")";
    }
}

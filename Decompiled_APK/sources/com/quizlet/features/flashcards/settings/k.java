package com.quizlet.features.flashcards.settings;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class k {
    public final a a;
    public final a b;
    public final boolean c;
    public final boolean d;
    public final n e;
    public final com.quizlet.features.infra.models.flashcards.c f;

    public k(a frontSideOptions, a aVar, boolean z, boolean z2, n nVar, com.quizlet.features.infra.models.flashcards.c flashcardMode) {
        Intrinsics.checkNotNullParameter(frontSideOptions, "frontSideOptions");
        Intrinsics.checkNotNullParameter(flashcardMode, "flashcardMode");
        this.a = frontSideOptions;
        this.b = aVar;
        this.c = z;
        this.d = z2;
        this.e = nVar;
        this.f = flashcardMode;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof k)) {
            return false;
        }
        k kVar = (k) obj;
        return Intrinsics.b(this.a, kVar.a) && Intrinsics.b(this.b, kVar.b) && this.c == kVar.c && this.d == kVar.d && Intrinsics.b(this.e, kVar.e) && this.f == kVar.f;
    }

    public final int hashCode() {
        int iHashCode = this.a.hashCode() * 31;
        a aVar = this.b;
        int iG = d0.g(d0.g((iHashCode + (aVar == null ? 0 : aVar.hashCode())) * 31, 31, this.c), 31, this.d);
        n nVar = this.e;
        return this.f.hashCode() + ((iG + (nVar != null ? Boolean.hashCode(nVar.d) : 0)) * 31);
    }

    public final String toString() {
        return "FlashcardsSettingsViewState(frontSideOptions=" + this.a + ", backSideOptions=" + this.b + ", shuffleEnabled=" + this.c + ", playAudioEnable=" + this.d + ", selectedCardsModeOptions=" + this.e + ", flashcardMode=" + this.f + ")";
    }
}

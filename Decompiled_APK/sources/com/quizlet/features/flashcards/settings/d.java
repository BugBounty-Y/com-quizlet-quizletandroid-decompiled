package com.quizlet.features.flashcards.settings;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class d {
    public final com.quizlet.features.infra.models.flashcards.d a;
    public final boolean b;
    public final boolean c;
    public final boolean d;

    public d(com.quizlet.features.infra.models.flashcards.d updatedSettings, boolean z, boolean z2, boolean z3) {
        Intrinsics.checkNotNullParameter(updatedSettings, "updatedSettings");
        this.a = updatedSettings;
        this.b = z;
        this.c = z2;
        this.d = z3;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof d)) {
            return false;
        }
        d dVar = (d) obj;
        return Intrinsics.b(this.a, dVar.a) && this.b == dVar.b && this.c == dVar.c && this.d == dVar.d;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.d) + d0.g(d0.g(this.a.hashCode() * 31, 31, this.b), 31, this.c);
    }

    public final String toString() {
        return "FlashcardsSettingsUpdateData(updatedSettings=" + this.a + ", shouldRestart=" + this.b + ", shouldReinitialize=" + this.c + ", shouldReload=" + this.d + ")";
    }
}

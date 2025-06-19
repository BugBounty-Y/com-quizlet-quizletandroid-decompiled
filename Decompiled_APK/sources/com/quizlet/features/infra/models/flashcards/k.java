package com.quizlet.features.infra.models.flashcards;

import com.google.android.gms.internal.mlkit_vision_barcode.D6;
import com.quizlet.studiablemodels.StudiableAudio;
import com.quizlet.studiablemodels.StudiableText;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class k extends D6 {
    public final StudiableText a;
    public final StudiableAudio b;
    public final boolean c;

    public k(StudiableText text, StudiableAudio studiableAudio) {
        Intrinsics.checkNotNullParameter(text, "text");
        this.a = text;
        this.b = studiableAudio;
        this.c = studiableAudio != null;
    }

    @Override // com.google.android.gms.internal.mlkit_vision_barcode.D6
    public final StudiableAudio b() {
        return this.b;
    }

    @Override // com.google.android.gms.internal.mlkit_vision_barcode.D6
    public final boolean c() {
        return this.c;
    }

    @Override // com.google.android.gms.internal.mlkit_vision_barcode.D6
    public final boolean d() {
        return false;
    }

    @Override // com.google.android.gms.internal.mlkit_vision_barcode.D6
    public final boolean e() {
        return true;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof k)) {
            return false;
        }
        k kVar = (k) obj;
        return Intrinsics.b(this.a, kVar.a) && Intrinsics.b(this.b, kVar.b);
    }

    public final int hashCode() {
        int iHashCode = this.a.hashCode() * 31;
        StudiableAudio studiableAudio = this.b;
        return (iHashCode + (studiableAudio == null ? 0 : studiableAudio.a.hashCode())) * 31;
    }

    public final String toString() {
        return "TextOnly(text=" + this.a + ", audio=" + this.b + ", voiceTranscription=null)";
    }
}

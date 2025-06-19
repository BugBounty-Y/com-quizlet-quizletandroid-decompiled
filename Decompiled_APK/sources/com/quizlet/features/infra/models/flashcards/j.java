package com.quizlet.features.infra.models.flashcards;

import com.google.android.gms.internal.mlkit_vision_barcode.D6;
import com.quizlet.studiablemodels.StudiableAudio;
import com.quizlet.studiablemodels.StudiableImage;
import com.quizlet.studiablemodels.StudiableText;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class j extends D6 {
    public final StudiableText a;
    public final StudiableImage b;
    public final StudiableAudio c;
    public final boolean d;

    public j(StudiableText text, StudiableImage image, StudiableAudio studiableAudio) {
        Intrinsics.checkNotNullParameter(text, "text");
        Intrinsics.checkNotNullParameter(image, "image");
        this.a = text;
        this.b = image;
        this.c = studiableAudio;
        this.d = studiableAudio != null;
    }

    @Override // com.google.android.gms.internal.mlkit_vision_barcode.D6
    public final StudiableAudio b() {
        return this.c;
    }

    @Override // com.google.android.gms.internal.mlkit_vision_barcode.D6
    public final boolean c() {
        return this.d;
    }

    @Override // com.google.android.gms.internal.mlkit_vision_barcode.D6
    public final boolean d() {
        return true;
    }

    @Override // com.google.android.gms.internal.mlkit_vision_barcode.D6
    public final boolean e() {
        return true;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof j)) {
            return false;
        }
        j jVar = (j) obj;
        return Intrinsics.b(this.a, jVar.a) && Intrinsics.b(this.b, jVar.b) && Intrinsics.b(this.c, jVar.c);
    }

    public final int hashCode() {
        int iHashCode = (this.b.hashCode() + (this.a.hashCode() * 31)) * 31;
        StudiableAudio studiableAudio = this.c;
        return (iHashCode + (studiableAudio == null ? 0 : studiableAudio.a.hashCode())) * 31;
    }

    public final String toString() {
        return "TextAndImage(text=" + this.a + ", image=" + this.b + ", audio=" + this.c + ", voiceTranscription=null)";
    }
}

package com.quizlet.features.infra.models.flashcards;

import com.google.android.gms.internal.mlkit_vision_barcode.D6;
import com.quizlet.studiablemodels.StudiableAudio;
import com.quizlet.studiablemodels.StudiableImage;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class g extends D6 {
    public final StudiableImage a;

    public g(StudiableImage image) {
        Intrinsics.checkNotNullParameter(image, "image");
        this.a = image;
    }

    @Override // com.google.android.gms.internal.mlkit_vision_barcode.D6
    public final StudiableAudio b() {
        return null;
    }

    @Override // com.google.android.gms.internal.mlkit_vision_barcode.D6
    public final boolean c() {
        return false;
    }

    @Override // com.google.android.gms.internal.mlkit_vision_barcode.D6
    public final boolean d() {
        return true;
    }

    @Override // com.google.android.gms.internal.mlkit_vision_barcode.D6
    public final boolean e() {
        return false;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof g) && Intrinsics.b(this.a, ((g) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "ImageOnly(image=" + this.a + ")";
    }
}

package com.quizlet.features.infra.models.flashcards;

import com.google.android.gms.internal.mlkit_vision_barcode.D6;
import com.quizlet.studiablemodels.StudiableAudio;
import com.quizlet.studiablemodels.diagrams.DiagramData;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b extends D6 {
    public final DiagramData a;

    public b(DiagramData diagram) {
        Intrinsics.checkNotNullParameter(diagram, "diagram");
        this.a = diagram;
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
        return false;
    }

    @Override // com.google.android.gms.internal.mlkit_vision_barcode.D6
    public final boolean e() {
        return false;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof b) && Intrinsics.b(this.a, ((b) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "DiagramOnly(diagram=" + this.a + ")";
    }
}

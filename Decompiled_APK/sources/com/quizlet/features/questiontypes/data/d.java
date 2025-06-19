package com.quizlet.features.questiontypes.data;

import com.google.android.gms.internal.mlkit_vision_camera.N2;
import com.quizlet.studiablemodels.StudiableImage;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class d extends N2 {
    public final com.quizlet.features.infra.models.a a;
    public final StudiableImage b;

    public d(com.quizlet.features.infra.models.a aVar, StudiableImage studiableImage) {
        this.a = aVar;
        this.b = studiableImage;
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
        com.quizlet.features.infra.models.a aVar = this.a;
        int iHashCode = (aVar == null ? 0 : aVar.hashCode()) * 31;
        StudiableImage studiableImage = this.b;
        return iHashCode + (studiableImage != null ? studiableImage.hashCode() : 0);
    }

    public final String toString() {
        return "StandardPrompt(contentTextData=" + this.a + ", image=" + this.b + ")";
    }
}

package com.quizlet.features.questiontypes.data;

import com.google.android.gms.internal.mlkit_vision_camera.N2;
import com.quizlet.studiablemodels.diagrams.DiagramData;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b extends N2 {
    public final DiagramData a;

    public b(DiagramData diagramData) {
        Intrinsics.checkNotNullParameter(diagramData, "diagramData");
        this.a = diagramData;
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
        return "DiagramPrompt(diagramData=" + this.a + ")";
    }
}

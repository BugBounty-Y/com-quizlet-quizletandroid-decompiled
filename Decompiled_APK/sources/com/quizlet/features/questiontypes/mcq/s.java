package com.quizlet.features.questiontypes.mcq;

import com.google.android.gms.internal.mlkit_vision_camera.X2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class s extends X2 {
    public final com.quizlet.diagrams.f a;

    public s(com.quizlet.diagrams.f termClickEvent) {
        Intrinsics.checkNotNullParameter(termClickEvent, "termClickEvent");
        this.a = termClickEvent;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof s) && Intrinsics.b(this.a, ((s) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "DiagramTermSelected(termClickEvent=" + this.a + ")";
    }
}

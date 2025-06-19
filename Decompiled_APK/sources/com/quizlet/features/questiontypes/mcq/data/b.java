package com.quizlet.features.questiontypes.mcq.data;

import com.google.android.gms.internal.mlkit_vision_camera.Y2;
import com.quizlet.studiablemodels.diagrams.DiagramData;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b extends Y2 {
    public final DiagramData a;
    public final Long b;
    public final Long c;
    public final Long d;
    public final Boolean e;
    public final com.quizlet.features.questiontypes.data.a f;

    public b(DiagramData diagramData, Long l, Long l2, Long l3, Boolean bool, com.quizlet.features.questiontypes.data.a labelState) {
        Intrinsics.checkNotNullParameter(diagramData, "diagramData");
        Intrinsics.checkNotNullParameter(labelState, "labelState");
        this.a = diagramData;
        this.b = l;
        this.c = l2;
        this.d = l3;
        this.e = bool;
        this.f = labelState;
    }

    @Override // com.google.android.gms.internal.mlkit_vision_camera.Y2
    public final com.quizlet.features.questiontypes.data.a c() {
        return this.f;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof b)) {
            return false;
        }
        b bVar = (b) obj;
        return Intrinsics.b(this.a, bVar.a) && Intrinsics.b(this.b, bVar.b) && Intrinsics.b(this.c, bVar.c) && Intrinsics.b(this.d, bVar.d) && Intrinsics.b(this.e, bVar.e) && Intrinsics.b(this.f, bVar.f);
    }

    public final int hashCode() {
        int iHashCode = this.a.hashCode() * 31;
        Long l = this.b;
        int iHashCode2 = (iHashCode + (l == null ? 0 : l.hashCode())) * 31;
        Long l2 = this.c;
        int iHashCode3 = (iHashCode2 + (l2 == null ? 0 : l2.hashCode())) * 31;
        Long l3 = this.d;
        int iHashCode4 = (iHashCode3 + (l3 == null ? 0 : l3.hashCode())) * 31;
        Boolean bool = this.e;
        return this.f.hashCode() + ((iHashCode4 + (bool != null ? bool.hashCode() : 0)) * 31);
    }

    public final String toString() {
        return "DiagramAnswer(diagramData=" + this.a + ", diagramCorrectId=" + this.b + ", diagramIncorrectId=" + this.c + ", selection=" + this.d + ", isCorrect=" + this.e + ", labelState=" + this.f + ")";
    }
}

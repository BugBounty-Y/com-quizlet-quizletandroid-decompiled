package com.quizlet.features.setpage.termlist.data;

import com.quizlet.studiablemodels.diagrams.DiagramData;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a {
    public final DiagramData a;

    public a(DiagramData diagramData) {
        this.a = diagramData;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof a) && Intrinsics.b(this.a, ((a) obj).a);
    }

    public final int hashCode() {
        DiagramData diagramData = this.a;
        if (diagramData == null) {
            return 0;
        }
        return diagramData.hashCode();
    }

    public final String toString() {
        return "DiagramUiData(diagramData=" + this.a + ")";
    }
}

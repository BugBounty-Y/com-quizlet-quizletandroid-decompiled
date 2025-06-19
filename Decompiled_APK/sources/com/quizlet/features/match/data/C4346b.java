package com.quizlet.features.match.data;

import androidx.camera.camera2.internal.AbstractC0147y;
import com.quizlet.studiablemodels.diagrams.DiagramData;
import java.util.ArrayList;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.features.match.data.b, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4346b extends AbstractC4353i {
    public final DiagramData a;
    public final ArrayList b;
    public final ArrayList c;

    public C4346b(DiagramData diagramData, ArrayList locationCards, ArrayList matchCards) {
        Intrinsics.checkNotNullParameter(diagramData, "diagramData");
        Intrinsics.checkNotNullParameter(locationCards, "locationCards");
        Intrinsics.checkNotNullParameter(matchCards, "matchCards");
        this.a = diagramData;
        this.b = locationCards;
        this.c = matchCards;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C4346b)) {
            return false;
        }
        C4346b c4346b = (C4346b) obj;
        return Intrinsics.b(this.a, c4346b.a) && this.b.equals(c4346b.b) && this.c.equals(c4346b.c);
    }

    public final int hashCode() {
        return this.c.hashCode() + androidx.compose.animation.d0.h(this.b, this.a.hashCode() * 31, 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("DiagramBoardData(diagramData=");
        sb.append(this.a);
        sb.append(", locationCards=");
        sb.append(this.b);
        sb.append(", matchCards=");
        return AbstractC0147y.f(")", sb, this.c);
    }
}

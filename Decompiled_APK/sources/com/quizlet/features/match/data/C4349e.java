package com.quizlet.features.match.data;

import com.quizlet.studiablemodels.StudiableDiagramShape;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.features.match.data.e, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4349e extends AbstractC4355k {
    public final long b;
    public final StudiableDiagramShape c;

    public C4349e(long j, StudiableDiagramShape shape) {
        Intrinsics.checkNotNullParameter(shape, "shape");
        this.b = j;
        this.c = shape;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C4349e)) {
            return false;
        }
        C4349e c4349e = (C4349e) obj;
        return this.b == c4349e.b && Intrinsics.b(this.c, c4349e.c);
    }

    public final int hashCode() {
        return this.c.a.hashCode() + (Long.hashCode(this.b) * 31);
    }

    public final String toString() {
        return "LocationMatchCardItem(id=" + this.b + ", shape=" + this.c + ")";
    }
}

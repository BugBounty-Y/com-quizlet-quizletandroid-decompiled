package com.quizlet.scandocument.model;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class c {
    public final String a;
    public final j b;

    public c(String description, j boundingPoly) {
        Intrinsics.checkNotNullParameter(description, "description");
        Intrinsics.checkNotNullParameter(boundingPoly, "boundingPoly");
        this.a = description;
        this.b = boundingPoly;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof c)) {
            return false;
        }
        c cVar = (c) obj;
        return Intrinsics.b(this.a, cVar.a) && Intrinsics.b(this.b, cVar.b);
    }

    public final int hashCode() {
        return this.b.a.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "OcrAnnotation(description=" + this.a + ", boundingPoly=" + this.b + ")";
    }
}

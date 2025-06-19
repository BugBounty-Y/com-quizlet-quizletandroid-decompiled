package com.quizlet.scandocument.model;

import androidx.camera.camera2.internal.AbstractC0147y;
import java.util.ArrayList;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class j {
    public final ArrayList a;

    public j(ArrayList vertices) {
        Intrinsics.checkNotNullParameter(vertices, "vertices");
        this.a = vertices;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof j) && this.a.equals(((j) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return AbstractC0147y.f(")", new StringBuilder("OcrPoly(vertices="), this.a);
    }
}

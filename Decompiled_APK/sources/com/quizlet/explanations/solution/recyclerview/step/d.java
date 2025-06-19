package com.quizlet.explanations.solution.recyclerview.step;

import com.quizlet.data.model.SimpleImage;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class d {
    public final SimpleImage a;
    public final SimpleImage b;

    public d(SimpleImage simpleImage, SimpleImage simpleImage2) {
        this.a = simpleImage;
        this.b = simpleImage2;
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
        SimpleImage simpleImage = this.a;
        int iHashCode = (simpleImage == null ? 0 : simpleImage.hashCode()) * 31;
        SimpleImage simpleImage2 = this.b;
        return iHashCode + (simpleImage2 != null ? simpleImage2.hashCode() : 0);
    }

    public final String toString() {
        return "SolutionStepColumnImages(latex=" + this.a + ", additional=" + this.b + ")";
    }
}

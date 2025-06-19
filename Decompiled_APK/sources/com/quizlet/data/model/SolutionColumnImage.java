package com.quizlet.data.model;

import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;

@com.squareup.moshi.m(generateAdapter = true)
@Metadata
/* loaded from: classes2.dex */
public final class SolutionColumnImage {
    public final SimpleImage a;
    public final SimpleImage b;

    public SolutionColumnImage(SimpleImage simpleImage, SimpleImage simpleImage2) {
        this.a = simpleImage;
        this.b = simpleImage2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof SolutionColumnImage)) {
            return false;
        }
        SolutionColumnImage solutionColumnImage = (SolutionColumnImage) obj;
        return Intrinsics.b(this.a, solutionColumnImage.a) && Intrinsics.b(this.b, solutionColumnImage.b);
    }

    public final int hashCode() {
        SimpleImage simpleImage = this.a;
        int iHashCode = (simpleImage == null ? 0 : simpleImage.hashCode()) * 31;
        SimpleImage simpleImage2 = this.b;
        return iHashCode + (simpleImage2 != null ? simpleImage2.hashCode() : 0);
    }

    public final String toString() {
        return "SolutionColumnImage(large=" + this.a + ", regular=" + this.b + ")";
    }

    public /* synthetic */ SolutionColumnImage(SimpleImage simpleImage, SimpleImage simpleImage2, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this((i & 1) != 0 ? null : simpleImage, simpleImage2);
    }
}

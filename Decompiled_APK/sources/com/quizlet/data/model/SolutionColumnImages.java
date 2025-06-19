package com.quizlet.data.model;

import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@com.squareup.moshi.m(generateAdapter = true)
@Metadata
/* loaded from: classes2.dex */
public final class SolutionColumnImages {
    public final SolutionColumnImage a;
    public final SolutionColumnImage b;

    public SolutionColumnImages(SolutionColumnImage solutionColumnImage, SolutionColumnImage solutionColumnImage2) {
        this.a = solutionColumnImage;
        this.b = solutionColumnImage2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof SolutionColumnImages)) {
            return false;
        }
        SolutionColumnImages solutionColumnImages = (SolutionColumnImages) obj;
        return Intrinsics.b(this.a, solutionColumnImages.a) && Intrinsics.b(this.b, solutionColumnImages.b);
    }

    public final int hashCode() {
        SolutionColumnImage solutionColumnImage = this.a;
        int iHashCode = (solutionColumnImage == null ? 0 : solutionColumnImage.hashCode()) * 31;
        SolutionColumnImage solutionColumnImage2 = this.b;
        return iHashCode + (solutionColumnImage2 != null ? solutionColumnImage2.hashCode() : 0);
    }

    public final String toString() {
        return "SolutionColumnImages(latex=" + this.a + ", additional=" + this.b + ")";
    }
}

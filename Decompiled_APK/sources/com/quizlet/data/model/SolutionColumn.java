package com.quizlet.data.model;

import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@com.squareup.moshi.m(generateAdapter = true)
@Metadata
/* loaded from: classes2.dex */
public final class SolutionColumn {
    public final String a;
    public final boolean b;
    public final SolutionColumnImages c;

    public SolutionColumn(String text, boolean z, SolutionColumnImages images) {
        Intrinsics.checkNotNullParameter(text, "text");
        Intrinsics.checkNotNullParameter(images, "images");
        this.a = text;
        this.b = z;
        this.c = images;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof SolutionColumn)) {
            return false;
        }
        SolutionColumn solutionColumn = (SolutionColumn) obj;
        return Intrinsics.b(this.a, solutionColumn.a) && this.b == solutionColumn.b && Intrinsics.b(this.c, solutionColumn.c);
    }

    public final int hashCode() {
        return this.c.hashCode() + androidx.compose.animation.d0.g(this.a.hashCode() * 31, 31, this.b);
    }

    public final String toString() {
        return "SolutionColumn(text=" + this.a + ", hasInvalidKatex=" + this.b + ", images=" + this.c + ")";
    }
}

package com.quizlet.scandocument.model;

import android.graphics.Bitmap;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class h {
    public final Bitmap a;
    public final d b;

    public h(Bitmap originalBitmap, d annotationData) {
        Intrinsics.checkNotNullParameter(originalBitmap, "originalBitmap");
        Intrinsics.checkNotNullParameter(annotationData, "annotationData");
        this.a = originalBitmap;
        this.b = annotationData;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof h)) {
            return false;
        }
        h hVar = (h) obj;
        return Intrinsics.b(this.a, hVar.a) && Intrinsics.b(this.b, hVar.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "OcrDocument(originalBitmap=" + this.a + ", annotationData=" + this.b + ")";
    }
}

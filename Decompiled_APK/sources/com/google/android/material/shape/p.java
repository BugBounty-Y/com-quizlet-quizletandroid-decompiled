package com.google.android.material.shape;

import android.graphics.Matrix;
import android.graphics.Path;

/* loaded from: classes2.dex */
public final class p extends q {
    public float b;
    public float c;

    @Override // com.google.android.material.shape.q
    public final void a(Matrix matrix, Path path) {
        Matrix matrix2 = this.a;
        matrix.invert(matrix2);
        path.transform(matrix2);
        path.lineTo(this.b, this.c);
        path.transform(matrix);
    }
}

package com.google.android.material.shape;

import android.graphics.Canvas;
import android.graphics.Matrix;
import java.util.ArrayList;
import java.util.Iterator;

/* loaded from: classes2.dex */
public final class l extends r {
    public final /* synthetic */ ArrayList c;
    public final /* synthetic */ Matrix d;

    public l(ArrayList arrayList, Matrix matrix) {
        this.c = arrayList;
        this.d = matrix;
    }

    @Override // com.google.android.material.shape.r
    public final void a(Matrix matrix, com.google.android.material.shadow.a aVar, int i, Canvas canvas) {
        Iterator it2 = this.c.iterator();
        while (it2.hasNext()) {
            ((r) it2.next()).a(this.d, aVar, i, canvas);
        }
    }
}

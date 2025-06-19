package androidx.emoji2.text;

import android.util.SparseArray;

/* loaded from: classes.dex */
public final class v {
    public final SparseArray a;
    public y b;

    public v(int i) {
        this.a = new SparseArray(i);
    }

    public final void a(y yVar, int i, int i2) {
        int iA = yVar.a(i);
        SparseArray sparseArray = this.a;
        v vVar = sparseArray == null ? null : (v) sparseArray.get(iA);
        if (vVar == null) {
            vVar = new v(1);
            sparseArray.put(yVar.a(i), vVar);
        }
        if (i2 > i) {
            vVar.a(yVar, i + 1, i2);
        } else {
            vVar.b = yVar;
        }
    }
}

package androidx.recyclerview.widget;

import android.util.SparseArray;
import java.util.Set;

/* loaded from: classes.dex */
public final class u0 {
    public SparseArray a;
    public int b;
    public Set c;

    public final t0 a(int i) {
        SparseArray sparseArray = this.a;
        t0 t0Var = (t0) sparseArray.get(i);
        if (t0Var != null) {
            return t0Var;
        }
        t0 t0Var2 = new t0();
        sparseArray.put(i, t0Var2);
        return t0Var2;
    }
}

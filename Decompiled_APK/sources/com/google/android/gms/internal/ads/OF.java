package com.google.android.gms.internal.ads;

import android.util.SparseArray;
import android.util.SparseBooleanArray;
import java.util.HashMap;
import java.util.Map;

/* loaded from: classes2.dex */
public final class OF extends C1701Ha {
    public final SparseArray A;
    public final SparseBooleanArray B;
    public final boolean t;
    public final boolean u;
    public final boolean v;
    public final boolean w;
    public final boolean x;
    public final boolean y;
    public final boolean z;

    public OF() {
        this.A = new SparseArray();
        this.B = new SparseBooleanArray();
        this.t = true;
        this.u = true;
        this.v = true;
        this.w = true;
        this.x = true;
        this.y = true;
        this.z = true;
    }

    public OF(PF pf) {
        a(pf);
        this.t = pf.t;
        this.u = pf.u;
        this.v = pf.v;
        this.w = pf.w;
        this.x = pf.x;
        this.y = pf.y;
        this.z = pf.z;
        SparseArray sparseArray = new SparseArray();
        int i = 0;
        while (true) {
            SparseArray sparseArray2 = pf.A;
            if (i < sparseArray2.size()) {
                sparseArray.put(sparseArray2.keyAt(i), new HashMap((Map) sparseArray2.valueAt(i)));
                i++;
            } else {
                this.A = sparseArray;
                this.B = pf.B.clone();
                return;
            }
        }
    }
}

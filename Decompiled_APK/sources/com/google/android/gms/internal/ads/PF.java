package com.google.android.gms.internal.ads;

import android.util.SparseArray;
import android.util.SparseBooleanArray;
import com.comscore.streaming.ContentMediaFormat;
import java.util.Map;
import java.util.Objects;

/* loaded from: classes2.dex */
public final class PF extends C1791Wa {
    public static final PF C = new PF(new OF());
    public final SparseArray A;
    public final SparseBooleanArray B;
    public final boolean t;
    public final boolean u;
    public final boolean v;
    public final boolean w;
    public final boolean x;
    public final boolean y;
    public final boolean z;

    static {
        String str = Yo.a;
        Integer.toString(1000, 36);
        Integer.toString(1001, 36);
        Integer.toString(1002, 36);
        Integer.toString(1003, 36);
        Integer.toString(1004, 36);
        Integer.toString(1005, 36);
        Integer.toString(1006, 36);
        Integer.toString(1007, 36);
        Integer.toString(1008, 36);
        Integer.toString(1009, 36);
        Integer.toString(1010, 36);
        Integer.toString(com.pubmatic.sdk.common.h.AD_EXPIRED, 36);
        Integer.toString(1012, 36);
        Integer.toString(1013, 36);
        Integer.toString(ContentMediaFormat.FULL_CONTENT_PODCAST, 36);
        Integer.toString(ContentMediaFormat.PARTIAL_CONTENT_PODCAST, 36);
        Integer.toString(1016, 36);
        Integer.toString(1017, 36);
        Integer.toString(1018, 36);
    }

    public PF(OF of) {
        super(of);
        this.t = of.t;
        this.u = of.u;
        this.v = of.v;
        this.w = of.w;
        this.x = of.x;
        this.y = of.y;
        this.z = of.z;
        this.A = of.A;
        this.B = of.B;
    }

    @Override // com.google.android.gms.internal.ads.C1791Wa
    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj != null && PF.class == obj.getClass()) {
            PF pf = (PF) obj;
            if (super.equals(pf) && this.t == pf.t && this.u == pf.u && this.v == pf.v && this.w == pf.w && this.x == pf.x && this.y == pf.y && this.z == pf.z) {
                SparseBooleanArray sparseBooleanArray = this.B;
                int size = sparseBooleanArray.size();
                SparseBooleanArray sparseBooleanArray2 = pf.B;
                if (sparseBooleanArray2.size() == size) {
                    int i = 0;
                    while (true) {
                        if (i >= size) {
                            SparseArray sparseArray = this.A;
                            int size2 = sparseArray.size();
                            SparseArray sparseArray2 = pf.A;
                            if (sparseArray2.size() == size2) {
                                for (int i2 = 0; i2 < size2; i2++) {
                                    int iIndexOfKey = sparseArray2.indexOfKey(sparseArray.keyAt(i2));
                                    if (iIndexOfKey >= 0) {
                                        Map map = (Map) sparseArray.valueAt(i2);
                                        Map map2 = (Map) sparseArray2.valueAt(iIndexOfKey);
                                        if (map2.size() == map.size()) {
                                            for (Map.Entry entry : map.entrySet()) {
                                                HF hf = (HF) entry.getKey();
                                                if (!map2.containsKey(hf) || !Objects.equals(entry.getValue(), map2.get(hf))) {
                                                }
                                            }
                                        }
                                    }
                                }
                                return true;
                            }
                        } else {
                            if (sparseBooleanArray2.indexOfKey(sparseBooleanArray.keyAt(i)) < 0) {
                                break;
                            }
                            i++;
                        }
                    }
                }
            }
        }
        return false;
    }

    @Override // com.google.android.gms.internal.ads.C1791Wa
    public final int hashCode() {
        return (((((((((((((((super.hashCode() + 31) * 31) + (this.t ? 1 : 0)) * 961) + (this.u ? 1 : 0)) * 961) + (this.v ? 1 : 0)) * 28629151) + (this.w ? 1 : 0)) * 31) + (this.x ? 1 : 0)) * 31) + (this.y ? 1 : 0)) * 961) + (this.z ? 1 : 0)) * 31;
    }
}

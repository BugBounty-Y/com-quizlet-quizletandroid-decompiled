package androidx.recyclerview.widget;

import android.util.SparseArray;
import java.util.List;

/* renamed from: androidx.recyclerview.widget.b, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1356b implements S0 {
    public Object a;

    public /* synthetic */ C1356b(Object obj) {
        this.a = obj;
    }

    @Override // androidx.recyclerview.widget.S0
    public X a(int i) {
        List list = (List) ((SparseArray) this.a).get(i);
        if (list == null || list.isEmpty()) {
            throw new IllegalArgumentException(android.support.v4.media.session.a.f(i, "Cannot find the wrapper for global view type "));
        }
        return (X) list.get(0);
    }

    @Override // androidx.recyclerview.widget.S0
    public R0 b(X x) {
        N0 n0 = new N0();
        n0.b = this;
        n0.a = x;
        return n0;
    }

    public void c(int i, int i2) {
        ((AbstractC1361d0) this.a).notifyItemRangeInserted(i, i2);
    }

    public void d(int i, int i2) {
        ((AbstractC1361d0) this.a).notifyItemRangeRemoved(i, i2);
    }
}

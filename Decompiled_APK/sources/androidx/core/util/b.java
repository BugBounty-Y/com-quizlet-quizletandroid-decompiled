package androidx.core.util;

import android.util.LongSparseArray;
import kotlin.collections.Q;

/* loaded from: classes.dex */
public final class b extends Q {
    public int a;
    final /* synthetic */ LongSparseArray<Object> b;

    public b(LongSparseArray longSparseArray) {
        this.b = longSparseArray;
    }

    @Override // kotlin.collections.Q
    public final long a() {
        LongSparseArray<Object> longSparseArray = this.b;
        int i = this.a;
        this.a = i + 1;
        return longSparseArray.keyAt(i);
    }

    @Override // java.util.Iterator
    public final boolean hasNext() {
        return this.a < this.b.size();
    }
}

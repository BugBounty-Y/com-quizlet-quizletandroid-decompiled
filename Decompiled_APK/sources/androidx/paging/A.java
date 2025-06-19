package androidx.paging;

import java.util.ArrayList;
import kotlin.collections.AbstractC4916g;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class A extends AbstractC4916g {
    public final int b;
    public final int c;
    public final ArrayList d;

    public A(ArrayList items, int i, int i2) {
        Intrinsics.checkNotNullParameter(items, "items");
        this.b = i;
        this.c = i2;
        this.d = items;
    }

    @Override // kotlin.collections.AbstractC4911b
    public final int a() {
        return this.d.size() + this.b + this.c;
    }

    @Override // java.util.List
    public final Object get(int i) {
        int i2 = this.b;
        if (i >= 0 && i < i2) {
            return null;
        }
        ArrayList arrayList = this.d;
        if (i < arrayList.size() + i2 && i2 <= i) {
            return arrayList.get(i - i2);
        }
        int size = arrayList.size() + i2;
        if (i < a() && size <= i) {
            return null;
        }
        StringBuilder sbV = android.support.v4.media.session.a.v(i, "Illegal attempt to access index ", " in ItemSnapshotList of size ");
        sbV.append(a());
        throw new IndexOutOfBoundsException(sbV.toString());
    }
}

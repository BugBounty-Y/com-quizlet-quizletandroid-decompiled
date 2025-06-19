package androidx.compose.runtime;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;

/* loaded from: classes.dex */
public final class B0 implements Iterable, kotlin.jvm.internal.markers.a {
    public final A0 a;
    public final int b;
    public final int c;

    public B0(A0 a0, int i, int i2) {
        this.a = a0;
        this.b = i;
        this.c = i2;
    }

    @Override // java.lang.Iterable
    public final Iterator iterator() {
        int i;
        ArrayList arrayList;
        int iE;
        A0 a0 = this.a;
        if (a0.h != this.c) {
            C0.f();
        }
        HashMap map = a0.j;
        C0774b c0774b = null;
        int i2 = this.b;
        if (map != null) {
            if (a0.g) {
                r.c("use active SlotWriter to crate an anchor for location instead");
            }
            if (i2 >= 0 && i2 < (i = a0.b) && (iE = C0.e((arrayList = a0.i), i2, i)) >= 0) {
                c0774b = (C0774b) arrayList.get(iE);
            }
            if (c0774b != null) {
            }
        }
        return new L(a0, i2 + 1, a0.a[(i2 * 5) + 3] + i2);
    }
}

package kotlin.collections;

import java.util.RandomAccess;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: kotlin.collections.f, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4915f extends AbstractC4916g implements RandomAccess {
    public final AbstractC4916g b;
    public final int c;
    public final int d;

    public C4915f(AbstractC4916g list, int i, int i2) {
        Intrinsics.checkNotNullParameter(list, "list");
        this.b = list;
        this.c = i;
        C4913d c4913d = AbstractC4916g.a;
        int iA = list.a();
        c4913d.getClass();
        C4913d.d(i, i2, iA);
        this.d = i2 - i;
    }

    @Override // kotlin.collections.AbstractC4911b
    public final int a() {
        return this.d;
    }

    @Override // java.util.List
    public final Object get(int i) {
        C4913d c4913d = AbstractC4916g.a;
        int i2 = this.d;
        c4913d.getClass();
        C4913d.b(i, i2);
        return this.b.get(this.c + i);
    }
}

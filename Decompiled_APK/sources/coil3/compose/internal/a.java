package coil3.compose.internal;

import coil3.m;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class a {
    public final Object a;
    public final coil3.compose.b b;
    public final m c;

    public a(Object obj, coil3.compose.b bVar, m mVar) {
        this.a = obj;
        this.b = bVar;
        this.c = mVar;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof a)) {
            return false;
        }
        a aVar = (a) obj;
        coil3.compose.b bVar = aVar.b;
        coil3.compose.b bVar2 = this.b;
        return Intrinsics.b(bVar2, bVar) && bVar2.a(this.a, aVar.a) && Intrinsics.b(this.c, aVar.c);
    }

    public final int hashCode() {
        coil3.compose.b bVar = this.b;
        return this.c.hashCode() + ((bVar.b(this.a) + (bVar.hashCode() * 31)) * 31);
    }
}

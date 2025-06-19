package coil3.compose;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class b {
    public static final b a = new b();

    public final boolean a(Object obj, Object obj2) {
        if (this == obj2) {
            return true;
        }
        if (!(obj instanceof coil3.request.g) || !(obj2 instanceof coil3.request.g)) {
            return Intrinsics.b(obj, obj2);
        }
        coil3.request.g gVar = (coil3.request.g) obj;
        coil3.request.g gVar2 = (coil3.request.g) obj2;
        return Intrinsics.b(gVar.a, gVar2.a) && gVar.b.equals(gVar2.b) && gVar.d.equals(gVar2.d) && Intrinsics.b(gVar.o, gVar2.o) && gVar.p == gVar2.p && gVar.q == gVar2.q;
    }

    public final int b(Object obj) {
        if (!(obj instanceof coil3.request.g)) {
            if (obj != null) {
                return obj.hashCode();
            }
            return 0;
        }
        coil3.request.g gVar = (coil3.request.g) obj;
        return gVar.q.hashCode() + ((gVar.p.hashCode() + ((gVar.o.hashCode() + assistantMode.refactored.a.d((gVar.b.hashCode() + (gVar.a.hashCode() * 31)) * 961, 961, gVar.d)) * 31)) * 31);
    }

    public final String toString() {
        return "AsyncImageModelEqualityDelegate.Default";
    }
}

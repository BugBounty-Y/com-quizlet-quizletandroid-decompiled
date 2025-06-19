package kotlin.collections;

import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Set;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public class a0 extends Z {
    public static HashSet c(Object... elements) {
        Intrinsics.checkNotNullParameter(elements, "elements");
        HashSet hashSet = new HashSet(U.a(elements.length));
        C4933y.L(elements, hashSet);
        return hashSet;
    }

    public static Set d(Object... elements) {
        Intrinsics.checkNotNullParameter(elements, "elements");
        LinkedHashSet linkedHashSet = new LinkedHashSet(U.a(elements.length));
        C4933y.L(elements, linkedHashSet);
        return linkedHashSet;
    }
}

package kotlin.collections;

import java.util.Collection;
import java.util.Iterator;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public class d0 {
    public static long[] a(Collection collection) {
        Intrinsics.checkNotNullParameter(collection, "<this>");
        long[] jArrA = kotlin.E.a(collection.size());
        Iterator it2 = collection.iterator();
        int i = 0;
        while (it2.hasNext()) {
            jArrA[i] = ((kotlin.D) it2.next()).a;
            i++;
        }
        return jArrA;
    }
}

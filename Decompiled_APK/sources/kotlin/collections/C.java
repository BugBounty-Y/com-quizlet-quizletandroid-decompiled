package kotlin.collections;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public class C extends B {
    public static int q(Iterable iterable, int i) {
        Intrinsics.checkNotNullParameter(iterable, "<this>");
        return iterable instanceof Collection ? ((Collection) iterable).size() : i;
    }

    public static ArrayList r(List list) {
        ArrayList arrayListM = assistantMode.refactored.a.m("<this>", list);
        Iterator it2 = list.iterator();
        while (it2.hasNext()) {
            G.u(arrayListM, (Iterable) it2.next());
        }
        return arrayListM;
    }
}

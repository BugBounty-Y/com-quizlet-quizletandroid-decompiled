package grading.impls;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import kotlin.collections.C;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;

/* loaded from: classes3.dex */
public final class g {
    public static final ArrayList a(String str) {
        List<String> listG = grading.core.g.g.g(0, str);
        ArrayList arrayList = new ArrayList(C.q(listG, 10));
        for (String str2 : listG) {
            Object obj = util.b.a;
            Intrinsics.checkNotNullParameter(str2, "<this>");
            arrayList.add(grading.core.g.b.replace(str2, ""));
        }
        ArrayList arrayList2 = new ArrayList(C.q(arrayList, 10));
        Iterator it2 = arrayList.iterator();
        while (it2.hasNext()) {
            arrayList2.add(StringsKt.g0((String) it2.next()).toString());
        }
        ArrayList arrayList3 = new ArrayList(C.q(arrayList2, 10));
        Iterator it3 = arrayList2.iterator();
        while (it3.hasNext()) {
            String str3 = (String) it3.next();
            Object obj2 = util.b.a;
            Intrinsics.checkNotNullParameter(str3, "<this>");
            arrayList3.add(grading.core.g.a.replace(str3, " "));
        }
        ArrayList arrayList4 = new ArrayList();
        Iterator it4 = arrayList3.iterator();
        while (it4.hasNext()) {
            Object next = it4.next();
            if (((String) next).length() > 0) {
                arrayList4.add(next);
            }
        }
        return arrayList4;
    }
}

package grading.factories;

import androidx.compose.animation.core.O0;
import grading.core.c;
import grading.impls.f;
import java.util.ArrayList;
import java.util.Arrays;
import kotlin.collections.C4930v;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a {
    public static final grading.core.a[] a;

    static {
        grading.core.a aVar = f.a;
        a = (grading.core.a[]) C4930v.s(new grading.core.a[]{f.a, f.c, f.d}, f.f);
    }

    public static grading.a a() {
        c[] cVarArr = grading.rules.a.a;
        ArrayList arrayList = new ArrayList(cVarArr.length);
        for (c cVar : cVarArr) {
            grading.core.a[] aVarArr = a;
            grading.core.a[] prefixClauses = (grading.core.a[]) Arrays.copyOf(aVarArr, aVarArr.length);
            cVar.getClass();
            Intrinsics.checkNotNullParameter(prefixClauses, "prefixClauses");
            String str = "(Prefixed) " + cVar.a;
            O0 o0 = new O0();
            o0.a(prefixClauses);
            o0.a(cVar.d);
            ArrayList arrayList2 = o0.a;
            arrayList.add(new c(str, cVar.b, cVar.c, (grading.core.a[]) arrayList2.toArray(new grading.core.a[arrayList2.size()])));
        }
        return new grading.a((c[]) arrayList.toArray(new c[0]));
    }
}

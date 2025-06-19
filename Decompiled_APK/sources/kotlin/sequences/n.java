package kotlin.sequences;

import java.util.Iterator;
import kotlin.collections.C4931w;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public class n extends k {
    public static a b(Iterator it2) {
        Intrinsics.checkNotNullParameter(it2, "<this>");
        C4931w c4931w = new C4931w(it2, 5);
        Intrinsics.checkNotNullParameter(c4931w, "<this>");
        return new a(c4931w);
    }

    public static Sequence c(Function1 nextFunction, Object obj) {
        Intrinsics.checkNotNullParameter(nextFunction, "nextFunction");
        return obj == null ? d.a : new g(new m(obj), nextFunction);
    }
}

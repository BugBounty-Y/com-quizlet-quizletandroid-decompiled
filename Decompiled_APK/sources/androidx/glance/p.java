package androidx.glance;

import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public interface p {
    Object a(Object obj, Function2 function2);

    boolean b();

    boolean c(Function1 function1);

    default p d(p pVar) {
        return pVar == n.a ? this : new h(this, pVar);
    }
}

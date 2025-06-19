package androidx.compose.ui;

import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public interface q {
    Object a(Object obj, Function2 function2);

    boolean d(Function1 function1);

    default q g(q qVar) {
        return qVar == n.b ? this : new k(this, qVar);
    }
}

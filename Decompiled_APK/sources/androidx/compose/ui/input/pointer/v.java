package androidx.compose.ui.input.pointer;

import kotlin.collections.K;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public abstract class v {
    public static final f a = new f(K.a, null);

    public static final androidx.compose.ui.q a(androidx.compose.ui.q qVar, Object obj, Function2 function2) {
        return qVar.g(new SuspendPointerInputElement(obj, null, function2, 6));
    }
}

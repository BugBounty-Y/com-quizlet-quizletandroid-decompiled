package androidx.compose.ui;

import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public interface o extends q {
    @Override // androidx.compose.ui.q
    default Object a(Object obj, Function2 function2) {
        return function2.invoke(obj, this);
    }

    @Override // androidx.compose.ui.q
    default boolean d(Function1 function1) {
        return ((Boolean) function1.invoke(this)).booleanValue();
    }
}

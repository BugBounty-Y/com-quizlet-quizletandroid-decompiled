package androidx.glance;

import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public interface o extends p {
    @Override // androidx.glance.p
    default Object a(Object obj, Function2 function2) {
        return function2.invoke(obj, this);
    }

    @Override // androidx.glance.p
    default boolean b() {
        return Boolean.TRUE.booleanValue();
    }

    @Override // androidx.glance.p
    default boolean c(Function1 function1) {
        return ((Boolean) function1.invoke(this)).booleanValue();
    }
}

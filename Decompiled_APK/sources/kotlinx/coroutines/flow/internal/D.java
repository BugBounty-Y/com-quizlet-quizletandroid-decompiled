package kotlinx.coroutines.flow.internal;

import kotlin.jvm.internal.C4956o;
import kotlinx.coroutines.flow.InterfaceC5002j;

/* loaded from: classes3.dex */
public final /* synthetic */ class D extends C4956o implements kotlin.jvm.functions.c {
    public static final D a = new D(3, InterfaceC5002j.class, "emit", "emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;", 0);

    @Override // kotlin.jvm.functions.c
    public final Object invoke(Object obj, Object obj2, Object obj3) {
        return ((InterfaceC5002j) obj).emit(obj2, (kotlin.coroutines.h) obj3);
    }
}

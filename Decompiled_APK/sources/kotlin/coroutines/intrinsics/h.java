package kotlin.coroutines.intrinsics;

import kotlin.coroutines.CoroutineContext;
import kotlin.coroutines.n;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.O;

/* loaded from: classes3.dex */
public class h {
    /* JADX WARN: Multi-variable type inference failed */
    public static kotlin.coroutines.h a(kotlin.coroutines.h hVar, kotlin.coroutines.h completion, Function2 function2) {
        Intrinsics.checkNotNullParameter(function2, "<this>");
        Intrinsics.checkNotNullParameter(completion, "completion");
        Intrinsics.checkNotNullParameter(completion, "completion");
        if (function2 instanceof kotlin.coroutines.jvm.internal.a) {
            return ((kotlin.coroutines.jvm.internal.a) function2).create(hVar, completion);
        }
        CoroutineContext context = completion.getContext();
        return context == n.a ? new d(completion, hVar, function2) : new e(completion, context, function2, hVar);
    }

    public static kotlin.coroutines.h b(kotlin.coroutines.h hVar) {
        kotlin.coroutines.h<Object> hVarIntercepted;
        Intrinsics.checkNotNullParameter(hVar, "<this>");
        kotlin.coroutines.jvm.internal.c cVar = hVar instanceof kotlin.coroutines.jvm.internal.c ? (kotlin.coroutines.jvm.internal.c) hVar : null;
        return (cVar == null || (hVarIntercepted = cVar.intercepted()) == null) ? hVar : hVarIntercepted;
    }

    public static Object c(Function2 function2, Object obj, kotlin.coroutines.h completion) {
        Intrinsics.checkNotNullParameter(function2, "<this>");
        Intrinsics.checkNotNullParameter(completion, "completion");
        Intrinsics.checkNotNullParameter(completion, "completion");
        CoroutineContext context = completion.getContext();
        Object fVar = context == n.a ? new f(completion) : new g(completion, context);
        O.d(2, function2);
        return function2.invoke(obj, fVar);
    }
}

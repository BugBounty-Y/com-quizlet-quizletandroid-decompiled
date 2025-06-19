package kotlinx.coroutines.flow.internal;

import com.quizlet.ui.compose.C4830x;
import kotlin.Unit;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.flow.InterfaceC5002j;

/* loaded from: classes3.dex */
public final class C extends kotlin.coroutines.jvm.internal.c implements InterfaceC5002j {
    public final InterfaceC5002j j;
    public final CoroutineContext k;
    public final int l;
    public CoroutineContext m;
    public kotlin.coroutines.h n;

    public C(InterfaceC5002j interfaceC5002j, CoroutineContext coroutineContext) {
        super(A.a, kotlin.coroutines.n.a);
        this.j = interfaceC5002j;
        this.k = coroutineContext;
        this.l = ((Number) coroutineContext.fold(0, new C4830x(18, (byte) 0))).intValue();
    }

    public final Object a(kotlin.coroutines.h hVar, Object obj) {
        CoroutineContext context = hVar.getContext();
        kotlinx.coroutines.E.o(context);
        CoroutineContext coroutineContext = this.m;
        if (coroutineContext != context) {
            if (coroutineContext instanceof x) {
                throw new IllegalStateException(kotlin.text.x.c("\n            Flow exception transparency is violated:\n                Previous 'emit' call has thrown exception " + ((x) coroutineContext).b + ", but then emission attempt of value '" + obj + "' has been detected.\n                Emissions from 'catch' blocks are prohibited in order to avoid unspecified behaviour, 'Flow.catch' operator can be used instead.\n                For a more detailed explanation, please refer to Flow documentation.\n            ").toString());
            }
            if (((Number) context.fold(0, new com.quizlet.features.settings.composables.dialogs.a(this, 24))).intValue() != this.l) {
                throw new IllegalStateException(("Flow invariant is violated:\n\t\tFlow was collected in " + this.k + ",\n\t\tbut emission happened in " + context + ".\n\t\tPlease refer to 'flow' documentation or use 'flowOn' instead").toString());
            }
            this.m = context;
        }
        this.n = hVar;
        D d = E.a;
        InterfaceC5002j interfaceC5002j = this.j;
        Intrinsics.e(interfaceC5002j, "null cannot be cast to non-null type kotlinx.coroutines.flow.FlowCollector<kotlin.Any?>");
        d.getClass();
        Object objEmit = interfaceC5002j.emit(obj, this);
        if (!Intrinsics.b(objEmit, kotlin.coroutines.intrinsics.a.a)) {
            this.n = null;
        }
        return objEmit;
    }

    @Override // kotlinx.coroutines.flow.InterfaceC5002j
    public final Object emit(Object obj, kotlin.coroutines.h frame) {
        try {
            Object objA = a(frame, obj);
            kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
            if (objA == aVar) {
                Intrinsics.checkNotNullParameter(frame, "frame");
            }
            return objA == aVar ? objA : Unit.a;
        } catch (Throwable th) {
            this.m = new x(frame.getContext(), th);
            throw th;
        }
    }

    @Override // kotlin.coroutines.jvm.internal.a, kotlin.coroutines.jvm.internal.d
    public final kotlin.coroutines.jvm.internal.d getCallerFrame() {
        kotlin.coroutines.h hVar = this.n;
        if (hVar instanceof kotlin.coroutines.jvm.internal.d) {
            return (kotlin.coroutines.jvm.internal.d) hVar;
        }
        return null;
    }

    @Override // kotlin.coroutines.jvm.internal.c, kotlin.coroutines.h
    public final CoroutineContext getContext() {
        CoroutineContext coroutineContext = this.m;
        return coroutineContext == null ? kotlin.coroutines.n.a : coroutineContext;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final StackTraceElement getStackTraceElement() {
        return null;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        Throwable thA = kotlin.r.a(obj);
        if (thA != null) {
            this.m = new x(getContext(), thA);
        }
        kotlin.coroutines.h hVar = this.n;
        if (hVar != null) {
            hVar.resumeWith(obj);
        }
        return kotlin.coroutines.intrinsics.a.a;
    }
}

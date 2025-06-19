package androidx.compose.foundation.gestures;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.compose.foundation.gestures.q, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0345q extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ C0350t l;
    public final /* synthetic */ Function2 m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0345q(C0350t c0350t, Function2 function2, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = c0350t;
        this.m = function2;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        C0345q c0345q = new C0345q(this.l, this.m, hVar);
        c0345q.k = obj;
        return c0345q;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C0345q) create((InterfaceC0334k0) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        C0350t c0350t = this.l;
        try {
            if (i == 0) {
                androidx.glance.appwidget.protobuf.Z.e(obj);
                InterfaceC0334k0 interfaceC0334k0 = (InterfaceC0334k0) this.k;
                ((androidx.compose.runtime.L0) c0350t.d).setValue(Boolean.TRUE);
                Function2 function2 = this.m;
                this.j = 1;
                if (function2.invoke(interfaceC0334k0, this) == aVar) {
                    return aVar;
                }
            } else {
                if (i != 1) {
                    throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                }
                androidx.glance.appwidget.protobuf.Z.e(obj);
            }
            ((androidx.compose.runtime.L0) c0350t.d).setValue(Boolean.FALSE);
            return Unit.a;
        } catch (Throwable th) {
            ((androidx.compose.runtime.L0) c0350t.d).setValue(Boolean.FALSE);
            throw th;
        }
    }
}

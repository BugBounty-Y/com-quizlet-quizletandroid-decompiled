package androidx.paging;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.flow.InterfaceC5002j;

/* renamed from: androidx.paging.d, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1309d extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ com.quizlet.remote.model.notes.e l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C1309d(com.quizlet.remote.model.notes.e eVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = eVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        C1309d c1309d = new C1309d(this.l, hVar);
        c1309d.k = obj;
        return c1309d;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C1309d) create((InterfaceC5002j) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            InterfaceC5002j interfaceC5002j = (InterfaceC5002j) this.k;
            kotlin.jvm.internal.H h = new kotlin.jvm.internal.H();
            h.a = Integer.MIN_VALUE;
            J0 j0 = new J0((kotlinx.coroutines.flow.x0) this.l.d, new C1303a(2, null), 4);
            C1307c c1307c = new C1307c(h, interfaceC5002j);
            this.j = 1;
            if (j0.b(c1307c, this) == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            androidx.glance.appwidget.protobuf.Z.e(obj);
        }
        return Unit.a;
    }
}

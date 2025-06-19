package androidx.paging.compose;

import androidx.glance.appwidget.protobuf.Z;
import androidx.paging.C1351y0;
import androidx.paging.F0;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class b extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ d l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(d dVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = dVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        b bVar = new b(this.l, hVar);
        bVar.k = obj;
        return bVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((b) create((C1351y0) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            C1351y0 c1351y0 = (C1351y0) this.k;
            c cVar = this.l.c;
            this.j = 1;
            cVar.getClass();
            Object objP = cVar.g.P(0, new F0(cVar, c1351y0, null), this);
            if (objP != aVar) {
                objP = Unit.a;
            }
            if (objP == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        return Unit.a;
    }
}

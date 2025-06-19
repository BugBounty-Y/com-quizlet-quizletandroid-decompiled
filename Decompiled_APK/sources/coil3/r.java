package coil3;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;
import kotlinx.coroutines.E;
import kotlinx.coroutines.I;
import kotlinx.coroutines.O;

/* loaded from: classes.dex */
public final class r extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ coil3.request.g l;
    public final /* synthetic */ u m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public r(u uVar, coil3.request.g gVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = gVar;
        this.m = uVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        r rVar = new r(this.m, this.l, hVar);
        rVar.k = obj;
        return rVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((r) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws Throwable {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i != 0) {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
            return obj;
        }
        Z.e(obj);
        C c = (C) this.k;
        kotlinx.coroutines.scheduling.e eVar = O.a;
        kotlinx.coroutines.android.d dVar = kotlinx.coroutines.internal.m.a.e;
        u uVar = this.m;
        coil3.request.g gVar = this.l;
        I iF = E.f(c, dVar, new q(uVar, gVar, null), 2);
        androidx.work.impl.model.l lVar = gVar.c;
        this.j = 1;
        Object objW = iF.w(this);
        return objW == aVar ? aVar : objW;
    }
}

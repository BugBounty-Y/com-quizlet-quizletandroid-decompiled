package androidx.room;

import androidx.glance.appwidget.protobuf.Z;
import androidx.work.impl.WorkDatabase_Impl;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.E;
import kotlinx.coroutines.flow.InterfaceC5002j;

/* loaded from: classes.dex */
public final class e extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ WorkDatabase_Impl l;
    public final /* synthetic */ String[] m;
    public final /* synthetic */ androidx.work.impl.model.s n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public e(WorkDatabase_Impl workDatabase_Impl, String[] strArr, androidx.work.impl.model.s sVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = workDatabase_Impl;
        this.m = strArr;
        this.n = sVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        e eVar = new e(this.l, this.m, this.n, hVar);
        eVar.k = obj;
        return eVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((e) create((InterfaceC5002j) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            d dVar = new d(this.l, (InterfaceC5002j) this.k, this.m, this.n, null);
            this.j = 1;
            if (E.m(dVar, this) == aVar) {
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

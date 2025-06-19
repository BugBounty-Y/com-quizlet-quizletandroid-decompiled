package androidx.room;

import androidx.glance.appwidget.protobuf.Z;
import androidx.work.impl.WorkDatabase_Impl;
import com.google.android.gms.internal.mlkit_vision_camera.D1;
import java.util.Map;
import java.util.concurrent.Executor;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.AbstractC5040y;
import kotlinx.coroutines.C;
import kotlinx.coroutines.E;
import kotlinx.coroutines.flow.InterfaceC5002j;
import kotlinx.coroutines.flow.e0;

/* loaded from: classes.dex */
public final class d extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ WorkDatabase_Impl l;
    public final /* synthetic */ InterfaceC5002j m;
    public final /* synthetic */ String[] n;
    public final /* synthetic */ androidx.work.impl.model.s o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public d(WorkDatabase_Impl workDatabase_Impl, InterfaceC5002j interfaceC5002j, String[] strArr, androidx.work.impl.model.s sVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = workDatabase_Impl;
        this.m = interfaceC5002j;
        this.n = strArr;
        this.o = sVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        d dVar = new d(this.l, this.m, this.n, this.o, hVar);
        dVar.k = obj;
        return dVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((d) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws Throwable {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            C c = (C) this.k;
            kotlinx.coroutines.channels.h hVarA = D1.a(-1, 6, null);
            c cVar = new c(this.n, hVarA, 0);
            Object obj2 = Unit.a;
            hVarA.o(obj2);
            if (c.getCoroutineContext().get(y.a) != null) {
                throw new ClassCastException();
            }
            WorkDatabase_Impl workDatabase_Impl = this.l;
            Map map = workDatabase_Impl.k;
            Object objP = map.get("QueryDispatcher");
            if (objP == null) {
                Executor executor = workDatabase_Impl.b;
                if (executor == null) {
                    Intrinsics.m("internalQueryExecutor");
                    throw null;
                }
                objP = E.p(executor);
                map.put("QueryDispatcher", objP);
            }
            kotlinx.coroutines.channels.h hVarA2 = D1.a(0, 7, null);
            E.A(c, (AbstractC5040y) objP, null, new b(workDatabase_Impl, cVar, hVarA, this.o, hVarA2, null), 2);
            this.j = 1;
            Object objO = e0.o(this.m, hVarA2, true, this);
            if (objO == aVar) {
                obj2 = objO;
            }
            if (obj2 == aVar) {
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

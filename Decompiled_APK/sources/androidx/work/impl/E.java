package androidx.work.impl;

import android.os.Build;
import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class E extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ F k;
    public final /* synthetic */ androidx.work.y l;
    public final /* synthetic */ androidx.work.impl.utils.p m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public E(F f, androidx.work.y yVar, androidx.work.impl.utils.p pVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = f;
        this.l = yVar;
        this.m = pVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new E(this.k, this.l, this.m, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((E) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws Throwable {
        Object objJ;
        Object obj2 = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        F f = this.k;
        androidx.work.y yVar = this.l;
        if (i == 0) {
            Z.e(obj);
            androidx.work.impl.model.q qVar = f.a;
            androidx.work.impl.utils.taskexecutor.c cVar = f.e;
            this.j = 1;
            int i2 = androidx.work.impl.utils.n.a;
            if (!qVar.q || Build.VERSION.SDK_INT >= 31) {
                objJ = Unit.a;
            } else {
                androidx.work.impl.utils.taskexecutor.b bVar = cVar.d;
                Intrinsics.checkNotNullExpressionValue(bVar, "taskExecutor.mainThreadExecutor");
                objJ = kotlinx.coroutines.E.J(kotlinx.coroutines.E.p(bVar), new androidx.work.impl.utils.m(yVar, qVar, this.m, f.b, null), this);
                if (objJ != obj2) {
                    objJ = Unit.a;
                }
            }
            if (objJ != obj2) {
            }
        }
        if (i != 1) {
            if (i != 2) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
            return obj;
        }
        Z.e(obj);
        String str = G.a;
        androidx.work.z.c().getClass();
        com.google.common.util.concurrent.e eVarStartWork = yVar.startWork();
        Intrinsics.checkNotNullExpressionValue(eVarStartWork, "worker.startWork()");
        this.j = 2;
        Object objA = G.a(eVarStartWork, yVar, this);
        return objA == obj2 ? obj2 : objA;
    }
}

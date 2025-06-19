package androidx.glance.session;

import android.content.Context;
import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class x extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ SessionWorker l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public x(SessionWorker sessionWorker, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = sessionWorker;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        x xVar = new x(this.l, hVar);
        xVar.k = obj;
        return xVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((x) create((K) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
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
        K k = (K) this.k;
        SessionWorker sessionWorker = this.l;
        Context applicationContext = sessionWorker.getApplicationContext();
        s sVar = new s(sessionWorker, k, null);
        w wVar = new w(sessionWorker, k, null);
        this.j = 1;
        Object objM = kotlinx.coroutines.E.m(new C1228f(applicationContext, wVar, sVar, null), this);
        return objM == aVar ? aVar : objM;
    }
}

package androidx.glance.session;

import androidx.glance.appwidget.C1182m;
import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class u extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ SessionWorker k;
    public final /* synthetic */ C1182m l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public u(SessionWorker sessionWorker, C1182m c1182m, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = sessionWorker;
        this.l = c1182m;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new u(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((u) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            InterfaceC1233k interfaceC1233k = this.k.h;
            t tVar = new t(this.l, null);
            this.j = 1;
            if (((p) interfaceC1233k).a(tVar, this) == aVar) {
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

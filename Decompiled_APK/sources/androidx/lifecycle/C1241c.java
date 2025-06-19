package androidx.lifecycle;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.lifecycle.c, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1241c extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ androidx.camera.camera2.internal.c0 l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C1241c(androidx.camera.camera2.internal.c0 c0Var, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = c0Var;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        C1241c c1241c = new C1241c(this.l, hVar);
        c1241c.k = obj;
        return c1241c;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C1241c) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws Exception {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        androidx.camera.camera2.internal.c0 c0Var = this.l;
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            V v = new V((C1249j) c0Var.b, ((kotlinx.coroutines.C) this.k).getCoroutineContext());
            C1259u c1259u = (C1259u) c0Var.c;
            this.j = 1;
            if (c1259u.invoke(v, this) == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            androidx.glance.appwidget.protobuf.Z.e(obj);
        }
        ((C1247h) c0Var.e).invoke();
        return Unit.a;
    }
}

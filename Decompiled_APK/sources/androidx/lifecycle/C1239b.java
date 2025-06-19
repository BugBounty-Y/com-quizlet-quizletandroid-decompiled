package androidx.lifecycle;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.lifecycle.b, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1239b extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ androidx.camera.camera2.internal.c0 k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C1239b(androidx.camera.camera2.internal.c0 c0Var, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = c0Var;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new C1239b(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C1239b) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        androidx.camera.camera2.internal.c0 c0Var = this.k;
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            c0Var.getClass();
            this.j = 1;
            if (kotlinx.coroutines.E.n(5000L, this) == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            androidx.glance.appwidget.protobuf.Z.e(obj);
        }
        if (!((C1249j) c0Var.b).e()) {
            kotlinx.coroutines.y0 y0Var = (kotlinx.coroutines.y0) c0Var.f;
            if (y0Var != null) {
                y0Var.j(null);
            }
            c0Var.f = null;
        }
        return Unit.a;
    }
}

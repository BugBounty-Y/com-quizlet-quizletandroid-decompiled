package androidx.compose.foundation.gestures;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.compose.foundation.gestures.l, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0335l extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ C0339n k;
    public final /* synthetic */ V l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0335l(C0339n c0339n, V v, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = c0339n;
        this.l = v;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new C0335l(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C0335l) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            C0339n c0339n = this.k;
            androidx.compose.foundation.y0 y0Var = c0339n.c;
            C0337m c0337m = c0339n.b;
            this.j = 1;
            androidx.compose.foundation.u0 u0Var = androidx.compose.foundation.u0.b;
            V v = this.l;
            y0Var.getClass();
            if (kotlinx.coroutines.E.m(new androidx.compose.foundation.x0(u0Var, y0Var, v, c0337m, null), this) == aVar) {
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

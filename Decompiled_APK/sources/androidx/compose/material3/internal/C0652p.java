package androidx.compose.material3.internal;

import androidx.compose.material.C0560c;
import kotlin.Pair;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.compose.material3.internal.p, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0652p extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ C0560c l;
    public final /* synthetic */ androidx.work.impl.model.t m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0652p(C0560c c0560c, androidx.work.impl.model.t tVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = c0560c;
        this.m = tVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        C0652p c0652p = new C0652p(this.l, this.m, hVar);
        c0652p.k = obj;
        return c0652p;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C0652p) create((Pair) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            Pair pair = (Pair) this.k;
            F f = (F) pair.a;
            r rVar = (r) this.m.n;
            this.j = 1;
            if (this.l.invoke(rVar, f, pair.b, this) == aVar) {
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

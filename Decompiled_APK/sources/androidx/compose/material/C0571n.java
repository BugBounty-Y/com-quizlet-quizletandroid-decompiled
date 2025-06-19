package androidx.compose.material;

import kotlin.Pair;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.compose.material.n, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0571n extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ C0560c l;
    public final /* synthetic */ C0575s m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0571n(C0560c c0560c, C0575s c0575s, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = c0560c;
        this.m = c0575s;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        C0571n c0571n = new C0571n(this.l, this.m, hVar);
        c0571n.k = obj;
        return c0571n;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C0571n) create((Pair) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            Pair pair = (Pair) this.k;
            G g = (G) pair.a;
            C0573p c0573p = this.m.m;
            this.j = 1;
            if (this.l.invoke(c0573p, g, pair.b, this) == aVar) {
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

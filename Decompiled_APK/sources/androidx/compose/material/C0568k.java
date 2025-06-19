package androidx.compose.material;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.compose.material.k, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0568k extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ C0574q l;
    public final /* synthetic */ C0575s m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0568k(C0574q c0574q, C0575s c0575s, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = c0574q;
        this.m = c0575s;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        C0568k c0568k = new C0568k(this.l, this.m, hVar);
        c0568k.k = obj;
        return c0568k;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C0568k) create((G) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            G g = (G) this.k;
            C0573p c0573p = this.m.m;
            this.j = 1;
            if (this.l.invoke(c0573p, g, this) == aVar) {
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

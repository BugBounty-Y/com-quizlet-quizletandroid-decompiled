package androidx.compose.foundation.gestures;

import androidx.compose.animation.C0278e;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.compose.foundation.gestures.v0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0355v0 extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ O l;
    public final /* synthetic */ L0 m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0355v0(O o, L0 l0, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = o;
        this.m = l0;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        C0355v0 c0355v0 = new C0355v0(this.l, this.m, hVar);
        c0355v0.k = obj;
        return c0355v0;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C0355v0) create((I0) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            C0278e c0278e = new C0278e(13, (I0) this.k, this.m);
            this.j = 1;
            if (this.l.invoke(c0278e, this) == aVar) {
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

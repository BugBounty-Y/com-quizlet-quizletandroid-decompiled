package androidx.compose.foundation.gestures;

import androidx.compose.animation.C0278e;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class V extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ O l;
    public final /* synthetic */ Y m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public V(O o, Y y, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = o;
        this.m = y;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        V v = new V(this.l, this.m, hVar);
        v.k = obj;
        return v;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((V) create((C0337m) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            C0278e c0278e = new C0278e(12, (C0337m) this.k, this.m);
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

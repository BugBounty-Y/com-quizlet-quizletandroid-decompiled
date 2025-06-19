package androidx.compose.foundation.gestures;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.compose.foundation.gestures.x0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0359x0 extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ Object j;
    public final /* synthetic */ long k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0359x0(long j, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = j;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        C0359x0 c0359x0 = new C0359x0(this.k, hVar);
        c0359x0.j = obj;
        return c0359x0;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C0359x0) create((I0) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        androidx.glance.appwidget.protobuf.Z.e(obj);
        L0 l0 = ((I0) this.j).a;
        L0.a(l0, l0.h, this.k, 1);
        return Unit.a;
    }
}

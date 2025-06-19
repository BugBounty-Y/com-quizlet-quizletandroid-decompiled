package androidx.compose.material3;

import kotlin.Unit;
import kotlin.jvm.functions.Function1;

/* renamed from: androidx.compose.material3.v2, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0745v2 extends kotlin.coroutines.jvm.internal.i implements kotlin.jvm.functions.c {
    public /* synthetic */ float j;
    public final /* synthetic */ Function1 k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0745v2(Function1 function1, kotlin.coroutines.h hVar) {
        super(3, hVar);
        this.k = function1;
    }

    @Override // kotlin.jvm.functions.c
    public final Object invoke(Object obj, Object obj2, Object obj3) {
        float fFloatValue = ((Number) obj2).floatValue();
        C0745v2 c0745v2 = new C0745v2(this.k, (kotlin.coroutines.h) obj3);
        c0745v2.j = fFloatValue;
        return c0745v2.invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        androidx.glance.appwidget.protobuf.Z.e(obj);
        this.k.invoke(new Float(this.j));
        return Unit.a;
    }
}

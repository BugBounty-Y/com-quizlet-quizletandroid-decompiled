package androidx.compose.runtime;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.compose.runtime.r0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0818r0 extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ Object j;

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        C0818r0 c0818r0 = new C0818r0(2, hVar);
        c0818r0.j = obj;
        return c0818r0;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C0818r0) create((EnumC0817q0) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        androidx.glance.appwidget.protobuf.Z.e(obj);
        return Boolean.valueOf(((EnumC0817q0) this.j) == EnumC0817q0.a);
    }
}

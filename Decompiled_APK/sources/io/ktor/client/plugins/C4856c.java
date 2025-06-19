package io.ktor.client.plugins;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: io.ktor.client.plugins.c, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4856c extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ Object j;

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        C4856c c4856c = new C4856c(2, hVar);
        c4856c.j = obj;
        return c4856c;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        ((C4856c) create((io.ktor.client.statement.b) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
        return null;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        androidx.glance.appwidget.protobuf.Z.e(obj);
        if (((io.ktor.client.statement.b) this.j).b().c().f().d(AbstractC4857d.b) == null) {
            return null;
        }
        throw new ClassCastException();
    }
}

package io.ktor.client.plugins;

import com.braze.C1483i;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: io.ktor.client.plugins.p, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4869p extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ Object j;
    public final /* synthetic */ boolean k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C4869p(boolean z, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = z;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        C4869p c4869p = new C4869p(this.k, hVar);
        c4869p.j = obj;
        return c4869p;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C4869p) create((io.ktor.client.request.c) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        androidx.glance.appwidget.protobuf.Z.e(obj);
        ((io.ktor.client.request.c) this.j).f.a(AbstractC4873u.c, new C1483i(this.k, 19));
        return Unit.a;
    }
}

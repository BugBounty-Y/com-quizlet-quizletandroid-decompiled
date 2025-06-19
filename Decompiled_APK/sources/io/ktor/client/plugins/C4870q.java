package io.ktor.client.plugins;

import java.util.List;
import kotlin.Unit;

/* renamed from: io.ktor.client.plugins.q, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4870q extends kotlin.coroutines.jvm.internal.i implements kotlin.jvm.functions.c {
    public final /* synthetic */ int j;
    public int k;
    public /* synthetic */ Object l;
    public /* synthetic */ Throwable m;
    public final /* synthetic */ List n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ C4870q(List list, kotlin.coroutines.h hVar, int i) {
        super(3, hVar);
        this.j = i;
        this.n = list;
    }

    @Override // kotlin.jvm.functions.c
    public final Object invoke(Object obj, Object obj2, Object obj3) {
        io.ktor.client.request.b bVar = (io.ktor.client.request.b) obj;
        Throwable th = (Throwable) obj2;
        kotlin.coroutines.h hVar = (kotlin.coroutines.h) obj3;
        switch (this.j) {
            case 0:
                C4870q c4870q = new C4870q(this.n, hVar, 0);
                c4870q.l = bVar;
                c4870q.m = th;
                return c4870q.invokeSuspend(Unit.a);
            default:
                C4870q c4870q2 = new C4870q(this.n, hVar, 1);
                c4870q2.l = bVar;
                c4870q2.m = th;
                return c4870q2.invokeSuspend(Unit.a);
        }
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        switch (this.j) {
            case 0:
                kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
                int i = this.k;
                if (i != 0) {
                    if (i != 1) {
                        throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                    }
                    Throwable th = (Throwable) this.l;
                    androidx.glance.appwidget.protobuf.Z.e(obj);
                    return th;
                }
                androidx.glance.appwidget.protobuf.Z.e(obj);
                io.ktor.client.request.b bVar = (io.ktor.client.request.b) this.l;
                Throwable thA = io.ktor.client.utils.a.a(this.m);
                this.l = thA;
                this.k = 1;
                return AbstractC4873u.a(this.n, thA, bVar, this) == aVar ? aVar : thA;
            default:
                kotlin.coroutines.intrinsics.a aVar2 = kotlin.coroutines.intrinsics.a.a;
                int i2 = this.k;
                if (i2 != 0) {
                    if (i2 != 1) {
                        throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                    }
                    Throwable th2 = (Throwable) this.l;
                    androidx.glance.appwidget.protobuf.Z.e(obj);
                    return th2;
                }
                androidx.glance.appwidget.protobuf.Z.e(obj);
                io.ktor.client.request.b bVar2 = (io.ktor.client.request.b) this.l;
                Throwable thA2 = io.ktor.client.utils.a.a(this.m);
                this.l = thA2;
                this.k = 1;
                return AbstractC4873u.a(this.n, thA2, bVar2, this) == aVar2 ? aVar2 : thA2;
        }
    }
}

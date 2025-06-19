package io.ktor.client.plugins;

import kotlin.Unit;

/* renamed from: io.ktor.client.plugins.b, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4855b extends kotlin.coroutines.jvm.internal.i implements kotlin.jvm.functions.c {
    public final /* synthetic */ int j;
    public int k;
    public /* synthetic */ io.ktor.util.pipeline.e l;
    public /* synthetic */ Object m;
    public final /* synthetic */ kotlin.jvm.functions.c n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ C4855b(kotlin.jvm.functions.c cVar, kotlin.coroutines.h hVar, int i) {
        super(3, hVar);
        this.j = i;
        this.n = cVar;
    }

    @Override // kotlin.jvm.functions.c
    public final Object invoke(Object obj, Object obj2, Object obj3) {
        io.ktor.util.pipeline.e eVar = (io.ktor.util.pipeline.e) obj;
        kotlin.coroutines.h hVar = (kotlin.coroutines.h) obj3;
        switch (this.j) {
            case 0:
                C4855b c4855b = new C4855b(this.n, hVar, 0);
                c4855b.l = eVar;
                c4855b.m = obj2;
                return c4855b.invokeSuspend(Unit.a);
            default:
                C4855b c4855b2 = new C4855b(this.n, hVar, 1);
                c4855b2.l = eVar;
                c4855b2.m = obj2;
                return c4855b2.invokeSuspend(Unit.a);
        }
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        io.ktor.util.pipeline.e eVar;
        io.ktor.util.pipeline.e eVar2;
        switch (this.j) {
            case 0:
                kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
                int i = this.k;
                if (i == 0) {
                    androidx.glance.appwidget.protobuf.Z.e(obj);
                    eVar = this.l;
                    Object obj2 = this.m;
                    if (!(obj2 instanceof io.ktor.http.content.c)) {
                        return Unit.a;
                    }
                    Object obj3 = eVar.a;
                    this.l = eVar;
                    this.k = 1;
                    obj = this.n.invoke(obj3, obj2, this);
                    if (obj == aVar) {
                        return aVar;
                    }
                } else {
                    if (i != 1) {
                        if (i != 2) {
                            throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                        }
                        androidx.glance.appwidget.protobuf.Z.e(obj);
                        return Unit.a;
                    }
                    eVar = this.l;
                    androidx.glance.appwidget.protobuf.Z.e(obj);
                }
                io.ktor.http.content.c cVar = (io.ktor.http.content.c) obj;
                if (cVar == null) {
                    return Unit.a;
                }
                this.l = null;
                this.k = 2;
                if (eVar.d(cVar, this) == aVar) {
                    return aVar;
                }
                return Unit.a;
            default:
                kotlin.coroutines.intrinsics.a aVar2 = kotlin.coroutines.intrinsics.a.a;
                int i2 = this.k;
                if (i2 == 0) {
                    androidx.glance.appwidget.protobuf.Z.e(obj);
                    eVar2 = this.l;
                    Object obj4 = this.m;
                    Object obj5 = eVar2.a;
                    this.l = eVar2;
                    this.k = 1;
                    obj = this.n.invoke(obj5, obj4, this);
                    if (obj == aVar2) {
                        return aVar2;
                    }
                } else {
                    if (i2 != 1) {
                        if (i2 != 2) {
                            throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                        }
                        androidx.glance.appwidget.protobuf.Z.e(obj);
                        return Unit.a;
                    }
                    eVar2 = this.l;
                    androidx.glance.appwidget.protobuf.Z.e(obj);
                }
                io.ktor.http.content.c cVar2 = (io.ktor.http.content.c) obj;
                if (cVar2 != null) {
                    this.l = null;
                    this.k = 2;
                    if (eVar2.d(cVar2, this) == aVar2) {
                        return aVar2;
                    }
                }
                return Unit.a;
        }
    }
}

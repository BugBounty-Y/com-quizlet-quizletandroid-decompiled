package io.ktor.client.engine;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;
import kotlinx.coroutines.C5023i0;
import kotlinx.coroutines.InterfaceC5025j0;

/* loaded from: classes3.dex */
public final class b extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ d k;
    public final /* synthetic */ io.ktor.client.request.d l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(d dVar, io.ktor.client.request.d dVar2, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = dVar;
        this.l = dVar2;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new b(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((b) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i != 0) {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
            return obj;
        }
        Z.e(obj);
        d dVar = this.k;
        InterfaceC5025j0 interfaceC5025j0 = (InterfaceC5025j0) dVar.getCoroutineContext().get(C5023i0.a);
        if (!(interfaceC5025j0 != null ? interfaceC5025j0.a() : false)) {
            throw new ClientEngineClosedException(0);
        }
        this.j = 1;
        Object objA = ((io.ktor.client.engine.okhttp.f) dVar).a(this.l, this);
        return objA == aVar ? aVar : objA;
    }
}

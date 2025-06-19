package com.quizlet.data.repository.metering;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.generated.enums.P;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.J;
import kotlinx.coroutines.C;
import kotlinx.coroutines.E;

/* loaded from: classes2.dex */
public final class d extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ Object j;
    public final /* synthetic */ J k;
    public final /* synthetic */ J l;
    public final /* synthetic */ j m;
    public final /* synthetic */ long n;
    public final /* synthetic */ Long o;
    public final /* synthetic */ P p;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public d(J j, J j2, j jVar, long j3, Long l, P p, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = j;
        this.l = j2;
        this.m = jVar;
        this.n = j3;
        this.o = l;
        this.p = p;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        d dVar = new d(this.k, this.l, this.m, this.n, this.o, this.p, hVar);
        dVar.j = obj;
        return dVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((d) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        C c = (C) this.j;
        this.k.a = E.f(c, null, new b(this.m, this.n, this.o, this.p, null), 3);
        this.l.a = E.f(c, null, new c(this.m, this.n, this.o, this.p, null), 3);
        return Unit.a;
    }
}

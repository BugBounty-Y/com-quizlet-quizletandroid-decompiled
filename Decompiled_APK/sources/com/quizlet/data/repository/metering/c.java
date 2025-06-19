package com.quizlet.data.repository.metering;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.generated.enums.P;
import java.io.Serializable;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes2.dex */
public final class c extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ j k;
    public final /* synthetic */ long l;
    public final /* synthetic */ Long m;
    public final /* synthetic */ P n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public c(j jVar, long j, Long l, P p, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = jVar;
        this.l = j;
        this.m = l;
        this.n = p;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new c(this.k, this.l, this.m, this.n, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((c) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
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
        j jVar = this.k;
        com.quizlet.data.repository.folderset.c cVar = (com.quizlet.data.repository.folderset.c) jVar.b;
        this.j = 1;
        Serializable serializableB = j.b(jVar, cVar, this.l, this.m, this.n, "Local", this);
        return serializableB == aVar ? aVar : serializableB;
    }
}

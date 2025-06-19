package com.quizlet.local.datastore.models.metering;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.generated.enums.P;
import java.util.NoSuchElementException;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class a extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public j j;
    public int k;
    public final /* synthetic */ com.quizlet.data.repository.folderset.c l;
    public final /* synthetic */ long m;
    public final /* synthetic */ Long n;
    public final /* synthetic */ P o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(com.quizlet.data.repository.folderset.c cVar, long j, Long l, P p, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = cVar;
        this.m = j;
        this.n = l;
        this.o = p;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new a(this.l, this.m, this.n, this.o, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((a) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        a aVar;
        j jVar;
        kotlin.coroutines.intrinsics.a aVar2 = kotlin.coroutines.intrinsics.a.a;
        int i = this.k;
        P p = this.o;
        com.quizlet.data.repository.folderset.c cVar = this.l;
        if (i == 0) {
            Z.e(obj);
            j jVar2 = (j) cVar.c;
            i iVar = (i) cVar.b;
            int iA = p.a();
            this.j = jVar2;
            this.k = 1;
            aVar = this;
            Object objA = iVar.a(this.m, this.n, iA, aVar);
            if (objA == aVar2) {
                return aVar2;
            }
            jVar = jVar2;
            obj = objA;
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            jVar = this.j;
            Z.e(obj);
            aVar = this;
        }
        d dVar = (d) obj;
        if (dVar != null) {
            jVar.getClass();
            return j.d(dVar);
        }
        cVar.getClass();
        throw new NoSuchElementException("Local MeteredEvent does not exist with userId=" + aVar.m + "&resourceId=" + aVar.n + "&eventType=" + p);
    }
}

package com.quizlet.data.interactor.folder;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.data.model.AbstractC4119d0;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes2.dex */
public final class b extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ c l;
    public final /* synthetic */ long m;
    public final /* synthetic */ long n;
    public final /* synthetic */ long o;
    public final /* synthetic */ boolean p;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(c cVar, long j, long j2, long j3, boolean z, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = cVar;
        this.m = j;
        this.n = j2;
        this.o = j3;
        this.p = z;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        b bVar = new b(this.l, this.m, this.n, this.o, this.p, hVar);
        bVar.k = obj;
        return bVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((b) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        Object objB;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        try {
            if (i == 0) {
                Z.e(obj);
                c cVar = this.l;
                long j = this.m;
                long j2 = this.n;
                long j3 = this.o;
                kotlin.p pVar = kotlin.r.b;
                com.quizlet.data.repository.folder.i iVar = cVar.a;
                boolean z = this.p;
                this.j = 1;
                obj = iVar.a(j, j2, j3, z, this);
                if (obj == aVar) {
                    return aVar;
                }
            } else {
                if (i != 1) {
                    throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                }
                Z.e(obj);
            }
            objB = (AbstractC4119d0) obj;
            kotlin.p pVar2 = kotlin.r.b;
        } catch (Throwable th) {
            kotlin.p pVar3 = kotlin.r.b;
            objB = Z.b(th);
        }
        return new kotlin.r(objB);
    }
}

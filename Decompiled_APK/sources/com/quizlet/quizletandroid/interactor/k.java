package com.quizlet.quizletandroid.interactor;

import java.io.Serializable;
import java.util.List;
import kotlin.Unit;
import kotlin.jvm.internal.J;
import kotlinx.coroutines.flow.InterfaceC5002j;

/* loaded from: classes3.dex */
public final class k extends kotlin.coroutines.jvm.internal.i implements kotlin.jvm.functions.c {
    public final /* synthetic */ int j;
    public int k;
    public /* synthetic */ Object l;
    public Object m;
    public Object n;
    public /* synthetic */ Object o;
    public final /* synthetic */ Object p;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public k(io.ktor.client.c cVar, kotlin.coroutines.h hVar) {
        super(3, hVar);
        this.j = 1;
        this.p = cVar;
    }

    @Override // kotlin.jvm.functions.c
    public final Object invoke(Object obj, Object obj2, Object obj3) {
        switch (this.j) {
            case 0:
                k kVar = new k((m) this.n, (J) this.o, (InterfaceC5002j) this.p, (kotlin.coroutines.h) obj3, 0);
                kVar.l = (List) obj;
                kVar.m = (List) obj2;
                return kVar.invokeSuspend(Unit.a);
            case 1:
                k kVar2 = new k((io.ktor.client.c) this.p, (kotlin.coroutines.h) obj3);
                kVar2.o = (io.ktor.util.pipeline.e) obj;
                kVar2.l = (io.ktor.client.statement.c) obj2;
                return kVar2.invokeSuspend(Unit.a);
            default:
                k kVar3 = new k((Long) this.n, (Long) this.o, (Long) this.p, (kotlin.coroutines.h) obj3, 2);
                kVar3.l = (io.ktor.client.plugins.api.g) obj;
                kVar3.m = (io.ktor.client.request.c) obj2;
                return kVar3.invokeSuspend(Unit.a);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:124:0x0360  */
    /* JADX WARN: Removed duplicated region for block: B:127:0x0368  */
    /* JADX WARN: Removed duplicated region for block: B:166:? A[RETURN, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:168:? A[RETURN, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:172:? A[RETURN, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:86:0x0247  */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r18) throws java.lang.Throwable {
        /*
            Method dump skipped, instructions count: 1112
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.interactor.k.invokeSuspend(java.lang.Object):java.lang.Object");
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ k(Object obj, Serializable serializable, Object obj2, kotlin.coroutines.h hVar, int i) {
        super(3, hVar);
        this.j = i;
        this.n = obj;
        this.o = serializable;
        this.p = obj2;
    }
}

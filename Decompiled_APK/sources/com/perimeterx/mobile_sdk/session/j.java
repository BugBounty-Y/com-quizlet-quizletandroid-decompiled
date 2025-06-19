package com.perimeterx.mobile_sdk.session;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.J;

/* loaded from: classes2.dex */
public final class j extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ int j;
    public kotlinx.coroutines.sync.c k;
    public String l;
    public int m;
    public final /* synthetic */ Object n;
    public Object o;
    public Object p;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public j(d dVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.j = 2;
        this.n = dVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        switch (this.j) {
            case 0:
                return new j((J) this.p, (String) this.n, hVar, 0);
            case 1:
                return new j((d) this.p, (String) this.n, hVar, 1);
            default:
                return new j((d) this.n, hVar);
        }
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        kotlin.coroutines.h hVar = (kotlin.coroutines.h) obj2;
        switch (this.j) {
            case 0:
                return new j((J) this.p, (String) this.n, hVar, 0).invokeSuspend(Unit.a);
            case 1:
                return new j((d) this.p, (String) this.n, hVar, 1).invokeSuspend(Unit.a);
            default:
                return new j((d) this.n, hVar).invokeSuspend(Unit.a);
        }
    }

    /* JADX WARN: Can't wrap try/catch for region: R(8:52|(1:(1:55)(2:56|57))(3:58|(1:61)|77)|81|62|(7:65|(1:90)|72|75|76|77|63)|87|73|74) */
    /* JADX WARN: Finally extract failed */
    /* JADX WARN: Removed duplicated region for block: B:23:0x0078 A[Catch: all -> 0x0087, LOOP:0: B:21:0x0072->B:23:0x0078, LOOP_END, TryCatch #1 {all -> 0x0087, blocks: (B:20:0x0067, B:21:0x0072, B:23:0x0078, B:26:0x0089), top: B:82:0x0067 }] */
    /* JADX WARN: Removed duplicated region for block: B:29:0x0099  */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r10) {
        /*
            Method dump skipped, instructions count: 372
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.perimeterx.mobile_sdk.session.j.invokeSuspend(java.lang.Object):java.lang.Object");
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ j(Object obj, String str, kotlin.coroutines.h hVar, int i) {
        super(2, hVar);
        this.j = i;
        this.p = obj;
        this.n = str;
    }
}

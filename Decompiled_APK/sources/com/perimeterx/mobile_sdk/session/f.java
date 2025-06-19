package com.perimeterx.mobile_sdk.session;

import androidx.glance.appwidget.protobuf.Z;
import java.io.Serializable;
import java.util.ArrayList;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.F;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.J;

/* loaded from: classes2.dex */
public final class f extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ int j;
    public kotlinx.coroutines.sync.c k;
    public int l;
    public Serializable m;
    public final /* synthetic */ Serializable n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ f(Serializable serializable, kotlin.coroutines.h hVar, int i) {
        super(2, hVar);
        this.j = i;
        this.n = serializable;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        switch (this.j) {
            case 0:
                return new f((J) this.n, hVar, 0);
            default:
                return new f((F) this.n, hVar, 1);
        }
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        kotlin.coroutines.h hVar = (kotlin.coroutines.h) obj2;
        switch (this.j) {
            case 0:
                return new f((J) this.n, hVar, 0).invokeSuspend(Unit.a);
            default:
                return new f((F) this.n, hVar, 1).invokeSuspend(Unit.a);
        }
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        J j;
        kotlinx.coroutines.sync.c cVar;
        F f;
        kotlinx.coroutines.sync.c cVar2;
        switch (this.j) {
            case 0:
                Object obj2 = kotlin.coroutines.intrinsics.a.a;
                int i = this.l;
                try {
                    if (i == 0) {
                        Z.e(obj);
                        kotlinx.coroutines.sync.c cVar3 = l.e;
                        this.k = cVar3;
                        j = (J) this.n;
                        this.m = j;
                        this.l = 1;
                        if (cVar3.d(this) != obj2) {
                            cVar = cVar3;
                        }
                        return obj2;
                    }
                    if (i != 1) {
                        throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                    }
                    j = (J) this.m;
                    cVar = this.k;
                    Z.e(obj);
                    Object objClone = l.c.clone();
                    Intrinsics.e(objClone, "null cannot be cast to non-null type java.util.ArrayList<com.perimeterx.mobile_sdk.session.PXSessionManager>");
                    j.a = (ArrayList) objClone;
                    obj2 = Unit.a;
                    return obj2;
                } finally {
                    cVar.f(null);
                }
            default:
                kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
                int i2 = this.l;
                if (i2 == 0) {
                    Z.e(obj);
                    kotlinx.coroutines.sync.c cVar4 = l.g;
                    f = (F) this.n;
                    this.k = cVar4;
                    this.m = f;
                    this.l = 1;
                    if (cVar4.d(this) == aVar) {
                        return aVar;
                    }
                    cVar2 = cVar4;
                } else {
                    if (i2 != 1) {
                        throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                    }
                    f = (F) this.m;
                    cVar2 = this.k;
                    Z.e(obj);
                }
                try {
                    long jCurrentTimeMillis = System.currentTimeMillis();
                    l lVar = l.a;
                    long j2 = jCurrentTimeMillis - l.h;
                    String str = com.perimeterx.mobile_sdk.configurations.i.a;
                    boolean z = ((double) j2) >= ((double) 300000) * 0.95d;
                    f.a = z;
                    if (z) {
                        l.h = jCurrentTimeMillis;
                    }
                    return Unit.a;
                } catch (Throwable th) {
                    throw th;
                }
        }
    }
}

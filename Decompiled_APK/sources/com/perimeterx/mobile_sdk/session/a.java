package com.perimeterx.mobile_sdk.session;

import android.os.Handler;
import android.os.Looper;
import androidx.glance.appwidget.protobuf.Z;
import androidx.navigation.U;
import java.util.Timer;
import kotlin.Unit;
import kotlin.collections.G;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.E;
import kotlinx.coroutines.O;

/* loaded from: classes2.dex */
public final class a extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ int j;
    public kotlinx.coroutines.sync.c k;
    public d l;
    public int m;
    public final /* synthetic */ d n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ a(d dVar, kotlin.coroutines.h hVar, int i) {
        super(2, hVar);
        this.j = i;
        this.n = dVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        switch (this.j) {
            case 0:
                return new a(this.n, hVar, 0);
            case 1:
                return new a(this.n, hVar, 1);
            case 2:
                return new a(this.n, hVar, 2);
            default:
                return new a(this.n, hVar, 3);
        }
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        kotlin.coroutines.h hVar = (kotlin.coroutines.h) obj2;
        switch (this.j) {
            case 0:
                return new a(this.n, hVar, 0).invokeSuspend(Unit.a);
            case 1:
                return new a(this.n, hVar, 1).invokeSuspend(Unit.a);
            case 2:
                return new a(this.n, hVar, 2).invokeSuspend(Unit.a);
            default:
                return new a(this.n, hVar, 3).invokeSuspend(Unit.a);
        }
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlinx.coroutines.sync.c cVar;
        d dVar;
        kotlinx.coroutines.sync.c cVar2;
        d dVar2;
        kotlinx.coroutines.sync.c cVar3;
        d dVar3;
        kotlinx.coroutines.sync.c cVar4;
        d dVar4;
        switch (this.j) {
            case 0:
                Object obj2 = kotlin.coroutines.intrinsics.a.a;
                int i = this.m;
                d dVar5 = this.n;
                try {
                    if (i == 0) {
                        Z.e(obj);
                        cVar = dVar5.d;
                        this.k = cVar;
                        this.l = dVar5;
                        this.m = 1;
                        if (cVar.d(this) != obj2) {
                            dVar = dVar5;
                        }
                        return obj2;
                    }
                    if (i != 1) {
                        throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                    }
                    dVar = this.l;
                    cVar = this.k;
                    Z.e(obj);
                    dVar.k = null;
                    obj2 = Unit.a;
                    cVar.f(null);
                    E.A(E.c(O.a), null, null, new j(dVar5, null), 3);
                    return obj2;
                } catch (Throwable th) {
                    cVar.f(null);
                    throw th;
                }
            case 1:
                Object obj3 = kotlin.coroutines.intrinsics.a.a;
                int i2 = this.m;
                try {
                    if (i2 == 0) {
                        Z.e(obj);
                        d dVar6 = this.n;
                        cVar2 = dVar6.d;
                        this.k = cVar2;
                        this.l = dVar6;
                        this.m = 1;
                        if (cVar2.d(this) != obj3) {
                            dVar2 = dVar6;
                        }
                        return obj3;
                    }
                    if (i2 != 1) {
                        throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                    }
                    dVar2 = this.l;
                    cVar2 = this.k;
                    Z.e(obj);
                    if (dVar2.k == null) {
                        try {
                            Timer timer = new Timer();
                            dVar2.k = timer;
                            new Handler(Looper.getMainLooper()).post(new com.google.firebase.crashlytics.internal.common.i(14, timer, dVar2));
                        } catch (Exception unused) {
                        }
                    }
                    obj3 = Unit.a;
                    return obj3;
                } finally {
                    cVar2.f(null);
                }
            case 2:
                Object objValueOf = kotlin.coroutines.intrinsics.a.a;
                int i3 = this.m;
                try {
                    if (i3 == 0) {
                        Z.e(obj);
                        cVar3 = l.e;
                        this.k = cVar3;
                        d dVar7 = this.n;
                        this.l = dVar7;
                        this.m = 1;
                        if (cVar3.d(this) != objValueOf) {
                            dVar3 = dVar7;
                        }
                        return objValueOf;
                    }
                    if (i3 != 1) {
                        throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                    }
                    dVar3 = this.l;
                    cVar3 = this.k;
                    Z.e(obj);
                    objValueOf = Boolean.valueOf(G.y(l.c, new U(dVar3, 9)));
                    return objValueOf;
                } finally {
                    cVar3.f(null);
                }
            default:
                Object objValueOf2 = kotlin.coroutines.intrinsics.a.a;
                int i4 = this.m;
                try {
                    if (i4 == 0) {
                        Z.e(obj);
                        cVar4 = l.e;
                        this.k = cVar4;
                        d dVar8 = this.n;
                        this.l = dVar8;
                        this.m = 1;
                        if (cVar4.d(this) != objValueOf2) {
                            dVar4 = dVar8;
                        }
                        return objValueOf2;
                    }
                    if (i4 != 1) {
                        throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                    }
                    dVar4 = this.l;
                    cVar4 = this.k;
                    Z.e(obj);
                    objValueOf2 = Boolean.valueOf(l.c.add(dVar4));
                    return objValueOf2;
                } finally {
                    cVar4.f(null);
                }
        }
    }
}

package com.perimeterx.mobile_sdk.session;

import androidx.glance.appwidget.protobuf.Z;
import java.util.HashMap;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class z extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ int j;
    public kotlinx.coroutines.sync.c k;
    public d l;
    public HashMap m;
    public int n;
    public final /* synthetic */ d o;
    public final /* synthetic */ HashMap p;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ z(d dVar, HashMap map, kotlin.coroutines.h hVar, int i) {
        super(2, hVar);
        this.j = i;
        this.o = dVar;
        this.p = map;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        switch (this.j) {
            case 0:
                return new z(this.o, this.p, hVar, 0);
            default:
                return new z(this.o, this.p, hVar, 1);
        }
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        kotlin.coroutines.h hVar = (kotlin.coroutines.h) obj2;
        switch (this.j) {
            case 0:
                return new z(this.o, this.p, hVar, 0).invokeSuspend(Unit.a);
            default:
                return new z(this.o, this.p, hVar, 1).invokeSuspend(Unit.a);
        }
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        d dVar;
        kotlinx.coroutines.sync.c cVar;
        HashMap map;
        d dVar2;
        kotlinx.coroutines.sync.c cVar2;
        HashMap map2;
        switch (this.j) {
            case 0:
                Object obj2 = kotlin.coroutines.intrinsics.a.a;
                int i = this.n;
                try {
                    if (i == 0) {
                        Z.e(obj);
                        dVar = this.o;
                        kotlinx.coroutines.sync.c cVar3 = dVar.d;
                        this.k = cVar3;
                        this.l = dVar;
                        HashMap map3 = this.p;
                        this.m = map3;
                        this.n = 1;
                        if (cVar3.d(this) != obj2) {
                            cVar = cVar3;
                            map = map3;
                        }
                        return obj2;
                    }
                    if (i != 1) {
                        throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                    }
                    map = this.m;
                    dVar = this.l;
                    cVar = this.k;
                    Z.e(obj);
                    m mVar = dVar.b;
                    mVar.getClass();
                    Intrinsics.checkNotNullParameter(map, "<set-?>");
                    mVar.n = map;
                    obj2 = Unit.a;
                    return obj2;
                } finally {
                    cVar.f(null);
                }
            default:
                Object obj3 = kotlin.coroutines.intrinsics.a.a;
                int i2 = this.n;
                try {
                    if (i2 == 0) {
                        Z.e(obj);
                        dVar2 = this.o;
                        kotlinx.coroutines.sync.c cVar4 = dVar2.d;
                        this.k = cVar4;
                        this.l = dVar2;
                        HashMap map4 = this.p;
                        this.m = map4;
                        this.n = 1;
                        if (cVar4.d(this) != obj3) {
                            cVar2 = cVar4;
                            map2 = map4;
                        }
                        return obj3;
                    }
                    if (i2 != 1) {
                        throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                    }
                    map2 = this.m;
                    dVar2 = this.l;
                    cVar2 = this.k;
                    Z.e(obj);
                    m mVar2 = dVar2.b;
                    mVar2.getClass();
                    Intrinsics.checkNotNullParameter(map2, "<set-?>");
                    mVar2.k = map2;
                    obj3 = Unit.a;
                    return obj3;
                } finally {
                    cVar2.f(null);
                }
        }
    }
}

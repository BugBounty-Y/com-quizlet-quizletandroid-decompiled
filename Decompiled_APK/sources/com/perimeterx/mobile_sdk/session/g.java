package com.perimeterx.mobile_sdk.session;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes2.dex */
public final class g extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ int j;
    public int k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ g(int i, int i2, kotlin.coroutines.h hVar) {
        super(i, hVar);
        this.j = i2;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        switch (this.j) {
            case 0:
                return new g(2, 0, hVar);
            case 1:
                return new g(2, 1, hVar);
            case 2:
                return new g(2, 2, hVar);
            default:
                return new g(2, 3, hVar);
        }
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        kotlin.coroutines.h hVar = (kotlin.coroutines.h) obj2;
        switch (this.j) {
            case 0:
                return new g(2, 0, hVar).invokeSuspend(Unit.a);
            case 1:
                return new g(2, 1, hVar).invokeSuspend(Unit.a);
            case 2:
                return new g(2, 2, hVar).invokeSuspend(Unit.a);
            default:
                return new g(2, 3, hVar).invokeSuspend(Unit.a);
        }
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        switch (this.j) {
            case 0:
                kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
                int i = this.k;
                if (i == 0) {
                    Z.e(obj);
                    l lVar = l.a;
                    com.perimeterx.mobile_sdk.api_data.j jVar = com.perimeterx.mobile_sdk.api_data.j.i;
                    this.k = 1;
                    if (l.c(jVar, this) == aVar) {
                        return aVar;
                    }
                } else {
                    if (i != 1) {
                        throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                    }
                    Z.e(obj);
                }
                return Unit.a;
            case 1:
                kotlin.coroutines.intrinsics.a aVar2 = kotlin.coroutines.intrinsics.a.a;
                int i2 = this.k;
                if (i2 == 0) {
                    Z.e(obj);
                    l lVar2 = l.a;
                    com.perimeterx.mobile_sdk.api_data.j jVar2 = com.perimeterx.mobile_sdk.api_data.j.g;
                    this.k = 1;
                    if (l.f(jVar2, this) == aVar2) {
                        return aVar2;
                    }
                } else {
                    if (i2 != 1) {
                        throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                    }
                    Z.e(obj);
                }
                return Unit.a;
            case 2:
                kotlin.coroutines.intrinsics.a aVar3 = kotlin.coroutines.intrinsics.a.a;
                int i3 = this.k;
                if (i3 == 0) {
                    Z.e(obj);
                    l lVar3 = l.a;
                    com.perimeterx.mobile_sdk.api_data.j jVar3 = com.perimeterx.mobile_sdk.api_data.j.e;
                    this.k = 1;
                    if (l.f(jVar3, this) == aVar3) {
                        return aVar3;
                    }
                } else {
                    if (i3 != 1) {
                        throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                    }
                    Z.e(obj);
                }
                return Unit.a;
            default:
                kotlin.coroutines.intrinsics.a aVar4 = kotlin.coroutines.intrinsics.a.a;
                int i4 = this.k;
                if (i4 == 0) {
                    Z.e(obj);
                    l lVar4 = l.a;
                    com.perimeterx.mobile_sdk.api_data.j jVar4 = com.perimeterx.mobile_sdk.api_data.j.f;
                    this.k = 1;
                    if (l.f(jVar4, this) == aVar4) {
                        return aVar4;
                    }
                } else {
                    if (i4 != 1) {
                        throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                    }
                    Z.e(obj);
                }
                return Unit.a;
        }
    }
}

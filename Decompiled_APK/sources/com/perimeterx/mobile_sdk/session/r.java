package com.perimeterx.mobile_sdk.session;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes2.dex */
public final class r extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ int j;
    public int k;
    public final /* synthetic */ d l;
    public final /* synthetic */ com.perimeterx.mobile_sdk.models.a m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ r(d dVar, com.perimeterx.mobile_sdk.models.a aVar, kotlin.coroutines.h hVar, int i) {
        super(2, hVar);
        this.j = i;
        this.l = dVar;
        this.m = aVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        switch (this.j) {
            case 0:
                return new r(this.l, this.m, hVar, 0);
            case 1:
                return new r(this.l, this.m, hVar, 1);
            default:
                return new r(this.l, this.m, hVar, 2);
        }
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        kotlin.coroutines.h hVar = (kotlin.coroutines.h) obj2;
        switch (this.j) {
            case 0:
                return new r(this.l, this.m, hVar, 0).invokeSuspend(Unit.a);
            case 1:
                return new r(this.l, this.m, hVar, 1).invokeSuspend(Unit.a);
            default:
                return new r(this.l, this.m, hVar, 2).invokeSuspend(Unit.a);
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
                    this.k = 1;
                    if (d.d(this.l, this.m, this) == aVar) {
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
                    this.k = 1;
                    if (d.d(this.l, this.m, this) == aVar2) {
                        return aVar2;
                    }
                } else {
                    if (i2 != 1) {
                        throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                    }
                    Z.e(obj);
                }
                return Unit.a;
            default:
                kotlin.coroutines.intrinsics.a aVar3 = kotlin.coroutines.intrinsics.a.a;
                int i3 = this.k;
                if (i3 == 0) {
                    Z.e(obj);
                    this.k = 1;
                    if (d.d(this.l, this.m, this) == aVar3) {
                        return aVar3;
                    }
                } else {
                    if (i3 != 1) {
                        throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                    }
                    Z.e(obj);
                }
                return Unit.a;
        }
    }
}

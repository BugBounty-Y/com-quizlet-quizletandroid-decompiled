package com.perimeterx.mobile_sdk.detections.device.touch_interception;

import androidx.glance.appwidget.protobuf.Z;
import com.perimeterx.mobile_sdk.session.l;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import kotlin.Unit;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class d extends i implements Function2 {
    public final /* synthetic */ int j;
    public kotlinx.coroutines.sync.c k;
    public int l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ d(int i, int i2, kotlin.coroutines.h hVar) {
        super(i, hVar);
        this.j = i2;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        switch (this.j) {
            case 0:
                return new d(2, 0, hVar);
            default:
                return new d(2, 1, hVar);
        }
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        kotlin.coroutines.h hVar = (kotlin.coroutines.h) obj2;
        switch (this.j) {
            case 0:
                return new d(2, 0, hVar).invokeSuspend(Unit.a);
            default:
                return new d(2, 1, hVar).invokeSuspend(Unit.a);
        }
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlinx.coroutines.sync.c cVar;
        kotlinx.coroutines.sync.c cVar2;
        switch (this.j) {
            case 0:
                kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
                int i = this.l;
                if (i == 0) {
                    Z.e(obj);
                    kotlinx.coroutines.sync.c cVar3 = e.h;
                    this.k = cVar3;
                    this.l = 1;
                    if (cVar3.d(this) == aVar) {
                        return aVar;
                    }
                    cVar = cVar3;
                } else {
                    if (i != 1) {
                        throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                    }
                    cVar = this.k;
                    Z.e(obj);
                }
                try {
                    for (Object obj2 : ((HashMap) e.e.c).keySet()) {
                        Intrinsics.checkNotNullExpressionValue(obj2, "next(...)");
                        ((HashMap) e.e.c).put((String) obj2, new ArrayList());
                    }
                    Unit unit = Unit.a;
                    cVar.f(null);
                    return unit;
                } finally {
                    cVar.f(null);
                }
            default:
                kotlin.coroutines.intrinsics.a aVar2 = kotlin.coroutines.intrinsics.a.a;
                int i2 = this.l;
                if (i2 == 0) {
                    Z.e(obj);
                    kotlinx.coroutines.sync.c cVar4 = l.e;
                    this.k = cVar4;
                    this.l = 1;
                    if (cVar4.d(this) == aVar2) {
                        return aVar2;
                    }
                    cVar2 = cVar4;
                } else {
                    if (i2 != 1) {
                        throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                    }
                    cVar2 = this.k;
                    Z.e(obj);
                }
                try {
                    Iterator it2 = l.c.iterator();
                    Intrinsics.checkNotNullExpressionValue(it2, "iterator(...)");
                    while (it2.hasNext()) {
                        Object next = it2.next();
                        Intrinsics.checkNotNullExpressionValue(next, "next(...)");
                        ((com.perimeterx.mobile_sdk.session.d) next).q();
                    }
                    Unit unit2 = Unit.a;
                    cVar2.f(null);
                    return unit2;
                } finally {
                    cVar2.f(null);
                }
        }
    }
}

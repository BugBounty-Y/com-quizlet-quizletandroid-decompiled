package com.perimeterx.mobile_sdk.detections.device.motion_interception;

import androidx.glance.appwidget.protobuf.Z;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class f extends i implements Function2 {
    public final /* synthetic */ int j;
    public kotlinx.coroutines.sync.c k;
    public ArrayList l;
    public int m;
    public final /* synthetic */ ArrayList n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ f(ArrayList arrayList, h hVar, int i) {
        super(2, hVar);
        this.j = i;
        this.n = arrayList;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        switch (this.j) {
            case 0:
                return new f(this.n, hVar, 0);
            default:
                return new f(this.n, hVar, 1);
        }
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        h hVar = (h) obj2;
        switch (this.j) {
            case 0:
                return new f(this.n, hVar, 0).invokeSuspend(Unit.a);
            default:
                return new f(this.n, hVar, 1).invokeSuspend(Unit.a);
        }
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlinx.coroutines.sync.c cVar;
        ArrayList arrayList;
        kotlinx.coroutines.sync.c cVar2;
        ArrayList arrayList2;
        switch (this.j) {
            case 0:
                Object obj2 = kotlin.coroutines.intrinsics.a.a;
                int i = this.m;
                try {
                    if (i == 0) {
                        Z.e(obj);
                        cVar = g.i;
                        this.k = cVar;
                        ArrayList arrayList3 = this.n;
                        this.l = arrayList3;
                        this.m = 1;
                        if (cVar.d(this) != obj2) {
                            arrayList = arrayList3;
                        }
                        return obj2;
                    }
                    if (i != 1) {
                        throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                    }
                    arrayList = this.l;
                    cVar = this.k;
                    Z.e(obj);
                    Iterator it2 = arrayList.iterator();
                    Intrinsics.checkNotNullExpressionValue(it2, "iterator(...)");
                    while (it2.hasNext()) {
                        Object next = it2.next();
                        Intrinsics.checkNotNullExpressionValue(next, "next(...)");
                        String str = (String) next;
                        HashMap map = g.h;
                        if (!map.keySet().contains(str)) {
                            map.put(str, new ArrayList());
                        }
                    }
                    obj2 = Unit.a;
                    cVar.f(null);
                    return obj2;
                } catch (Throwable th) {
                    cVar.f(null);
                    throw th;
                }
            default:
                Object obj3 = kotlin.coroutines.intrinsics.a.a;
                int i2 = this.m;
                try {
                    if (i2 == 0) {
                        Z.e(obj);
                        cVar2 = com.perimeterx.mobile_sdk.detections.device.touch_interception.e.h;
                        this.k = cVar2;
                        ArrayList arrayList4 = this.n;
                        this.l = arrayList4;
                        this.m = 1;
                        if (cVar2.d(this) != obj3) {
                            arrayList2 = arrayList4;
                        }
                        return obj3;
                    }
                    if (i2 != 1) {
                        throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                    }
                    arrayList2 = this.l;
                    cVar2 = this.k;
                    Z.e(obj);
                    Iterator it3 = arrayList2.iterator();
                    Intrinsics.checkNotNullExpressionValue(it3, "iterator(...)");
                    while (it3.hasNext()) {
                        Object next2 = it3.next();
                        Intrinsics.checkNotNullExpressionValue(next2, "next(...)");
                        String str2 = (String) next2;
                        com.quizlet.data.interactor.school.b bVar = com.perimeterx.mobile_sdk.detections.device.touch_interception.e.e;
                        if (!((HashMap) bVar.c).keySet().contains(str2)) {
                            ((HashMap) bVar.c).put(str2, new ArrayList());
                        }
                    }
                    obj3 = Unit.a;
                    cVar2.f(null);
                    return obj3;
                } catch (Throwable th2) {
                    cVar2.f(null);
                    throw th2;
                }
        }
    }
}

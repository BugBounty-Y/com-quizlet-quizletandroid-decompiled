package com.quizlet.qutils.coroutines;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.Pair;
import kotlin.Unit;

/* loaded from: classes3.dex */
public final class a extends kotlin.coroutines.jvm.internal.i implements kotlin.jvm.functions.c {
    public final /* synthetic */ int j;
    public /* synthetic */ Object k;
    public /* synthetic */ Object l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ a(int i, int i2, kotlin.coroutines.h hVar) {
        super(i, hVar);
        this.j = i2;
    }

    @Override // kotlin.jvm.functions.c
    public final Object invoke(Object obj, Object obj2, Object obj3) {
        kotlin.coroutines.h hVar = (kotlin.coroutines.h) obj3;
        switch (this.j) {
            case 0:
                a aVar = new a(3, 0, hVar);
                aVar.k = obj;
                aVar.l = obj2;
                return aVar.invokeSuspend(Unit.a);
            default:
                a aVar2 = new a(3, 1, hVar);
                aVar2.k = obj;
                aVar2.l = obj2;
                return aVar2.invokeSuspend(Unit.a);
        }
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        switch (this.j) {
            case 0:
                kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
                Z.e(obj);
                break;
            default:
                kotlin.coroutines.intrinsics.a aVar2 = kotlin.coroutines.intrinsics.a.a;
                Z.e(obj);
                break;
        }
        return new Pair(this.k, this.l);
    }
}

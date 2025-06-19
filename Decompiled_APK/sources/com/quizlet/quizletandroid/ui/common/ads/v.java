package com.quizlet.quizletandroid.ui.common.ads;

import androidx.glance.appwidget.protobuf.Z;
import java.util.Map;
import kotlin.Pair;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final class v extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ Object j;
    public final /* synthetic */ E k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public v(E e, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = e;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        v vVar = new v(this.k, hVar);
        vVar.j = obj;
        return vVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((v) create((Pair) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        Object pair;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        Pair pair2 = (Pair) this.j;
        C4634a c4634a = (C4634a) pair2.a;
        Map map = (Map) pair2.b;
        if (!c4634a.e) {
            kotlin.p pVar = kotlin.r.b;
            pair = Z.b(new IllegalStateException("User is not connected to fetch an ad"));
        } else if (c4634a.c) {
            kotlin.p pVar2 = kotlin.r.b;
            pair = new Pair(c4634a, map);
        } else {
            kotlin.p pVar3 = kotlin.r.b;
            pair = Z.b(new IllegalStateException("User is not eligible for ads"));
        }
        return new kotlin.r(pair);
    }
}

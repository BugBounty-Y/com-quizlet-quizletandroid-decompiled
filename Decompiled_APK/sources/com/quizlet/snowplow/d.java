package com.quizlet.snowplow;

import androidx.glance.appwidget.protobuf.Z;
import com.snowplowanalytics.core.tracker.k;
import com.snowplowanalytics.core.tracker.l;
import com.snowplowanalytics.core.tracker.o;
import kotlin.Pair;
import kotlin.Unit;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class d extends i implements Function2 {
    public /* synthetic */ Object j;

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        d dVar = new d(2, hVar);
        dVar.j = obj;
        return dVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((d) create((Pair) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        Pair pair = (Pair) this.j;
        Long l = (Long) pair.a;
        k serviceProvider = (k) ((o) pair.b).b;
        com.snowplowanalytics.core.media.controller.a aVar2 = serviceProvider.f;
        if (aVar2 == null) {
            Intrinsics.checkNotNullParameter(serviceProvider, "serviceProvider");
            aVar2 = new com.snowplowanalytics.core.media.controller.a(serviceProvider);
            serviceProvider.f = aVar2;
        }
        String string = l != null ? l.toString() : null;
        k kVar = (k) aVar2.b;
        com.snowplowanalytics.snowplow.configuration.h hVar = kVar.i;
        if (hVar == null) {
            Intrinsics.m("subjectConfiguration");
            throw null;
        }
        hVar.b = string;
        l lVarC = kVar.c();
        lVarC.getClass();
        lVarC.a.put("uid", string);
        return Unit.a;
    }
}

package com.quizlet.search.viewmodels;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.eventlogger.features.search.SearchEventLogger;
import kotlin.Pair;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.search.viewmodels.a, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4795a extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ Object j;
    public final /* synthetic */ AbstractC4797c k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C4795a(AbstractC4797c abstractC4797c, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = abstractC4797c;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        C4795a c4795a = new C4795a(this.k, hVar);
        c4795a.j = obj;
        return c4795a;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C4795a) create((Pair) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        Pair pair = (Pair) this.j;
        Boolean bool = pair != null ? (Boolean) pair.a : null;
        String str = pair != null ? (String) pair.b : null;
        if (str == null) {
            str = "";
        }
        AbstractC4797c abstractC4797c = this.k;
        if (abstractC4797c.e && Intrinsics.b(bool, Boolean.TRUE)) {
            abstractC4797c.e = false;
            boolean z = abstractC4797c.f;
            SearchEventLogger searchEventLogger = abstractC4797c.b;
            if (z) {
                searchEventLogger.z(abstractC4797c.A(), str);
            } else {
                searchEventLogger.u(abstractC4797c.A(), str);
            }
        }
        return Unit.a;
    }
}

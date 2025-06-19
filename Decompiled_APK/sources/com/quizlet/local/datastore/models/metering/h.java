package com.quizlet.local.datastore.models.metering;

import androidx.glance.appwidget.protobuf.Z;
import com.google.protobuf.AbstractC4025t;
import com.google.protobuf.AbstractC4027v;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class h extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ Object j;
    public final /* synthetic */ String k;
    public final /* synthetic */ d l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public h(String str, d dVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = str;
        this.l = dVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        h hVar2 = new h(this.k, this.l, hVar);
        hVar2.j = obj;
        return hVar2;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((h) create((n) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        n nVar = (n) this.j;
        AbstractC4025t abstractC4025t = (AbstractC4025t) nVar.l(5);
        if (!abstractC4025t.a.equals(nVar)) {
            abstractC4025t.k();
            AbstractC4025t.l(abstractC4025t.b, nVar);
        }
        l lVar = (l) abstractC4025t;
        String str = this.k;
        str.getClass();
        d dVar = this.l;
        dVar.getClass();
        lVar.k();
        n.w((n) lVar.b).put(str, dVar);
        AbstractC4027v abstractC4027vH = lVar.h();
        Intrinsics.checkNotNullExpressionValue(abstractC4027vH, "build(...)");
        return abstractC4027vH;
    }
}

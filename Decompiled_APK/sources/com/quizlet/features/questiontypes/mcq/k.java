package com.quizlet.features.questiontypes.mcq;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.diagrams.ui.DiagramJSBridge;
import java.util.Arrays;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class k extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ com.quizlet.features.questiontypes.mcq.data.b j;
    public final /* synthetic */ l k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public k(com.quizlet.features.questiontypes.mcq.data.b bVar, l lVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.j = bVar;
        this.k = lVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new k(this.j, this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((k) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        com.quizlet.features.questiontypes.mcq.data.b bVar = this.j;
        Long l = bVar.d;
        l lVar = this.k;
        if (l != null) {
            long jLongValue = l.longValue();
            DiagramJSBridge diagramJSBridge = lVar.g;
            diagramJSBridge.getClass();
            String str = String.format("onSelectTerm('%d');", Arrays.copyOf(new Object[]{Long.valueOf(jLongValue)}, 1));
            Intrinsics.checkNotNullExpressionValue(str, "format(...)");
            diagramJSBridge.executeJs$diagrams_release(str);
        }
        Long l2 = bVar.b;
        if (l2 != null) {
            lVar.g.a(l2.longValue());
        }
        Long l3 = bVar.c;
        if (l3 != null) {
            lVar.g.b(l3.longValue());
        }
        return Unit.a;
    }
}

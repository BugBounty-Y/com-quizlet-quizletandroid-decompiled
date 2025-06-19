package com.quizlet.features.folders.addtofolder.viewmodel;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.features.folders.addtofolder.data.p;
import com.quizlet.features.folders.addtofolder.data.u;
import java.util.List;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.flow.s0;

/* loaded from: classes3.dex */
public final class g extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ Object j;
    public final /* synthetic */ m k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public g(m mVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = mVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        g gVar = new g(this.k, hVar);
        gVar.j = obj;
        return gVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((g) create((List) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        s0 s0Var;
        Object value;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        List list = (List) this.j;
        m mVar = this.k;
        do {
            s0Var = mVar.j;
            value = s0Var.getValue();
        } while (!s0Var.k(value, u.a((u) value, null, null, null, new p(list), null, null, null, false, null, 0, null, 0, 0, 16375)));
        list.isEmpty();
        return Unit.a;
    }
}

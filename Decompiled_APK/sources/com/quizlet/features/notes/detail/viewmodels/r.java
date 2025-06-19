package com.quizlet.features.notes.detail.viewmodels;

import androidx.glance.appwidget.protobuf.Z;
import java.util.ArrayList;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;
import kotlinx.coroutines.flow.s0;

/* loaded from: classes3.dex */
public final class r extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ v j;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public r(v vVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.j = vVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new r(this.j, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((r) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        s0 s0Var;
        Object value;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        v vVar = this.j;
        vVar.getClass();
        ArrayList arrayList = new ArrayList();
        if (vVar.z) {
            arrayList.add(com.quizlet.features.notes.detail.menu.b.a);
            arrayList.add(com.quizlet.features.notes.detail.menu.e.a);
            arrayList.add(com.quizlet.features.notes.detail.menu.c.a);
        }
        arrayList.add(com.quizlet.features.notes.detail.menu.d.a);
        if (vVar.z) {
            arrayList.add(com.quizlet.features.notes.detail.menu.a.a);
        }
        do {
            s0Var = vVar.s;
            value = s0Var.getValue();
        } while (!s0Var.k(value, new com.quizlet.features.notes.detail.menu.m(arrayList)));
        return Unit.a;
    }
}

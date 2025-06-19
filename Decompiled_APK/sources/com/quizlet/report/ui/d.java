package com.quizlet.report.ui;

import androidx.compose.runtime.InterfaceC0773a0;
import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.report.data.o;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class d extends i implements Function2 {
    public final /* synthetic */ o j;
    public final /* synthetic */ InterfaceC0773a0 k;
    public final /* synthetic */ InterfaceC0773a0 l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public d(o oVar, InterfaceC0773a0 interfaceC0773a0, InterfaceC0773a0 interfaceC0773a02, h hVar) {
        super(2, hVar);
        this.j = oVar;
        this.k = interfaceC0773a0;
        this.l = interfaceC0773a02;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new d(this.j, this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((d) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        o oVar = this.j;
        this.k.setValue(oVar.b);
        Integer num = oVar.b;
        if (num != null) {
            this.l.setValue(Boolean.valueOf(((com.quizlet.report.data.a) oVar.a.a().get(num.intValue())).c));
        }
        return Unit.a;
    }
}

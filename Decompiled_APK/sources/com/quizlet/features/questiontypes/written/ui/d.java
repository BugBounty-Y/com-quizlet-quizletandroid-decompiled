package com.quizlet.features.questiontypes.written.ui;

import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.ui.focus.p;
import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class d extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ i j;
    public final /* synthetic */ p k;
    public final /* synthetic */ InterfaceC0773a0 l;
    public final /* synthetic */ InterfaceC0773a0 m;
    public final /* synthetic */ InterfaceC0773a0 n;
    public final /* synthetic */ InterfaceC0773a0 o;
    public final /* synthetic */ InterfaceC0773a0 p;
    public final /* synthetic */ InterfaceC0773a0 q;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public d(i iVar, p pVar, InterfaceC0773a0 interfaceC0773a0, InterfaceC0773a0 interfaceC0773a02, InterfaceC0773a0 interfaceC0773a03, InterfaceC0773a0 interfaceC0773a04, InterfaceC0773a0 interfaceC0773a05, InterfaceC0773a0 interfaceC0773a06, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.j = iVar;
        this.k = pVar;
        this.l = interfaceC0773a0;
        this.m = interfaceC0773a02;
        this.n = interfaceC0773a03;
        this.o = interfaceC0773a04;
        this.p = interfaceC0773a05;
        this.q = interfaceC0773a06;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new d(this.j, this.k, this.l, this.m, this.n, this.o, this.p, this.q, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((d) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        i iVar = this.j;
        this.l.setValue(iVar.a);
        this.m.setValue(Boolean.valueOf(iVar.c));
        Boolean boolValueOf = Boolean.valueOf(iVar.d);
        InterfaceC0773a0 interfaceC0773a0 = this.n;
        interfaceC0773a0.setValue(boolValueOf);
        this.o.setValue(Boolean.valueOf(iVar.e));
        this.p.setValue(Boolean.FALSE);
        this.q.setValue(null);
        boolean zBooleanValue = ((Boolean) interfaceC0773a0.getValue()).booleanValue();
        p pVar = this.k;
        if (zBooleanValue) {
            pVar.b();
        } else {
            pVar.c();
        }
        return Unit.a;
    }
}

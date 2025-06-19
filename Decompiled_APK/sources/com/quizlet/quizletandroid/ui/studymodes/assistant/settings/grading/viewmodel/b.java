package com.quizlet.quizletandroid.ui.studymodes.assistant.settings.grading.viewmodel;

import androidx.glance.appwidget.protobuf.Z;
import androidx.lifecycle.p0;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;
import kotlinx.coroutines.E;

/* loaded from: classes3.dex */
public final class b extends i implements Function2 {
    public int j;
    public final /* synthetic */ g k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(g gVar, h hVar) {
        super(2, hVar);
        this.k = gVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new b(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((b) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws Throwable {
        Object obj2 = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        g gVar = this.k;
        if (i == 0) {
            Z.e(obj);
            this.j = 1;
            gVar.getClass();
            Object objJ = E.J(gVar.c, new c(gVar, null), this);
            if (objJ != obj2) {
                objJ = Unit.a;
            }
            if (objJ == obj2) {
                return obj2;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        gVar.getClass();
        E.A(p0.j(gVar), null, null, new e(gVar, null), 3);
        gVar.j.m();
        return Unit.a;
    }
}

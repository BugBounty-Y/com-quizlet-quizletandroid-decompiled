package com.quizlet.quizletandroid.ui.studymodes.match.viewmodel;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;
import kotlinx.coroutines.E;
import kotlinx.coroutines.InterfaceC5025j0;
import kotlinx.coroutines.O;

/* loaded from: classes3.dex */
public final class f extends i implements Function2 {
    public int j;
    public final /* synthetic */ g k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public f(g gVar, h hVar) {
        super(2, hVar);
        this.k = gVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new f(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((f) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws Throwable {
        Object obj2 = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            g gVar = this.k;
            InterfaceC5025j0 interfaceC5025j0 = gVar.x;
            if (interfaceC5025j0 != null) {
                interfaceC5025j0.j(null);
            }
            this.j = 1;
            com.quizlet.quizletandroid.audio.players.c cVar = gVar.e;
            cVar.getClass();
            kotlinx.coroutines.scheduling.e eVar = O.a;
            Object objJ = E.J(kotlinx.coroutines.scheduling.d.b, new com.quizlet.quizletandroid.audio.players.b(cVar, null), this);
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
        return Unit.a;
    }
}

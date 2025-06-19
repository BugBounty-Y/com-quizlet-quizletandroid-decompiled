package com.quizlet.login.intro.ui;

import androidx.compose.runtime.L0;
import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.login.intro.data.u;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class j extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ u j;
    public final /* synthetic */ com.quizlet.assembly.compose.toasts.g k;
    public final /* synthetic */ com.quizlet.assembly.compose.toasts.g l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public j(u uVar, com.quizlet.assembly.compose.toasts.g gVar, com.quizlet.assembly.compose.toasts.g gVar2, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.j = uVar;
        this.k = gVar;
        this.l = gVar2;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new j(this.j, this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((j) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        u uVar = this.j;
        if (uVar.a != null) {
            ((L0) this.k.b).setValue(Boolean.TRUE);
        }
        if (uVar.b) {
            ((L0) this.l.b).setValue(Boolean.TRUE);
        }
        return Unit.a;
    }
}

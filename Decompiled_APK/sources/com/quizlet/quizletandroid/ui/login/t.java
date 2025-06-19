package com.quizlet.quizletandroid.ui.login;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.E;

/* loaded from: classes3.dex */
public final class t extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ Object j;
    public final /* synthetic */ ParentEmailFragment k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public t(ParentEmailFragment parentEmailFragment, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = parentEmailFragment;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        t tVar = new t(this.k, hVar);
        tVar.j = obj;
        return tVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((t) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        kotlinx.coroutines.C c = (kotlinx.coroutines.C) this.j;
        ParentEmailFragment parentEmailFragment = this.k;
        E.A(c, null, null, new r(parentEmailFragment, null), 3);
        E.A(c, null, null, new s(parentEmailFragment, null), 3);
        return Unit.a;
    }
}

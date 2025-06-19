package com.quizlet.quizletandroid.ui.deeplinkinterstitial;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;
import kotlinx.coroutines.flow.s0;

/* loaded from: classes3.dex */
public final class g extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ i k;
    public final /* synthetic */ com.quizlet.infra.androidcontracts.deeplink.a l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public g(i iVar, com.quizlet.infra.androidcontracts.deeplink.a aVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = iVar;
        this.l = aVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new g(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((g) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        Object value;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        i iVar = this.k;
        if (i == 0) {
            Z.e(obj);
            com.google.firebase.crashlytics.internal.settings.b bVar = iVar.f;
            this.j = 1;
            obj = bVar.d(this);
            if (obj == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        boolean zBooleanValue = ((Boolean) obj).booleanValue();
        s0 s0Var = iVar.g;
        do {
            value = s0Var.getValue();
        } while (!s0Var.k(value, new a(this.l, zBooleanValue)));
        return Unit.a;
    }
}

package com.braze.models.inappmessage;

import androidx.glance.appwidget.protobuf.Z;
import com.braze.managers.C1500m;
import com.braze.managers.c0;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes.dex */
public final class c extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ String a;
    public final /* synthetic */ InAppMessageBase b;
    public final /* synthetic */ c0 c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public c(String str, InAppMessageBase inAppMessageBase, c0 c0Var, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.a = str;
        this.b = inAppMessageBase;
        this.c = c0Var;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new c(this.a, this.b, this.c, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((c) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        com.braze.models.i iVarM = com.braze.models.outgoing.event.b.g.m(this.a, this.b.getMessageExtras());
        if (iVarM != null) {
            ((C1500m) this.c).a(iVarM);
        }
        return Unit.a;
    }
}

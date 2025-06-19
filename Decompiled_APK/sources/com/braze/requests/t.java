package com.braze.requests;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes.dex */
public final class t extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ u a;
    public final /* synthetic */ com.braze.requests.framework.h b;
    public final /* synthetic */ com.braze.requests.framework.c c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public t(u uVar, com.braze.requests.framework.h hVar, com.braze.requests.framework.c cVar, kotlin.coroutines.h hVar2) {
        super(2, hVar2);
        this.a = uVar;
        this.b = hVar;
        this.c = cVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new t(this.a, this.b, this.c, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((t) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        u uVar = this.a;
        new d(this.b, uVar.a, uVar.b, uVar.c, uVar.d, uVar.g, uVar.e, uVar.f, uVar.h, this.c).c();
        return Unit.a;
    }
}

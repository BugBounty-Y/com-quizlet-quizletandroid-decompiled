package com.braze.triggers.managers;

import androidx.compose.animation.d0;
import androidx.glance.appwidget.protobuf.Z;
import com.braze.support.BrazeLogger;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final class d extends kotlin.coroutines.jvm.internal.i implements Function1 {
    public final /* synthetic */ com.braze.triggers.actions.a a;
    public final /* synthetic */ f b;
    public final /* synthetic */ com.braze.triggers.events.b c;
    public final /* synthetic */ long d;
    public final /* synthetic */ long e;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public d(com.braze.triggers.actions.a aVar, f fVar, com.braze.triggers.events.b bVar, long j, long j2, kotlin.coroutines.h hVar) {
        super(1, hVar);
        this.a = aVar;
        this.b = fVar;
        this.c = bVar;
        this.d = j;
        this.e = j2;
    }

    public static final String a(long j) {
        return d0.o(j, "Performing triggered action after a delay of ", " ms.");
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(kotlin.coroutines.h hVar) {
        return new d(this.a, this.b, this.c, this.d, this.e, hVar);
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        return ((d) create((kotlin.coroutines.h) obj)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, f.q, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new com.braze.dispatch.j(9, this.e), 14, (Object) null);
        com.braze.triggers.actions.a aVar2 = this.a;
        f fVar = this.b;
        aVar2.a(fVar.a, fVar.c, this.c, this.d);
        return Unit.a;
    }
}

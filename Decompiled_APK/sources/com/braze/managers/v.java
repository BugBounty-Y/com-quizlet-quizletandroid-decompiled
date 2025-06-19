package com.braze.managers;

import androidx.glance.appwidget.protobuf.Z;
import com.braze.support.BrazeLogger;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final class v extends kotlin.coroutines.jvm.internal.i implements Function1 {
    public final /* synthetic */ y a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public v(y yVar, kotlin.coroutines.h hVar) {
        super(1, hVar);
        this.a = yVar;
    }

    public static final String a() {
        return "Ending subscription on a delay";
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(kotlin.coroutines.h hVar) {
        return new v(this.a, hVar);
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        return new v(this.a, (kotlin.coroutines.h) obj).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this.a, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new P(20), 7, (Object) null);
        this.a.a();
        return Unit.a;
    }
}

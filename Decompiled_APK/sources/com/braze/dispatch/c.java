package com.braze.dispatch;

import android.content.BroadcastReceiver;
import android.content.Intent;
import androidx.glance.appwidget.protobuf.Z;
import com.braze.events.internal.o;
import com.braze.support.BrazeLogger;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes.dex */
public final class c extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ Object a;
    public final /* synthetic */ f b;
    public final /* synthetic */ Intent c;
    public final /* synthetic */ BroadcastReceiver.PendingResult d;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public c(f fVar, Intent intent, BroadcastReceiver.PendingResult pendingResult, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.b = fVar;
        this.c = intent;
        this.d = pendingResult;
    }

    public static final String a() {
        return "Retrieving connectivity event data in background";
    }

    public static final String b() {
        return "Failed to process connectivity event.";
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        c cVar = new c(this.b, this.c, this.d, hVar);
        cVar.a = obj;
        return cVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((c) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        C c = (C) this.a;
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) c, BrazeLogger.Priority.V, (Throwable) null, false, (Function0) new com.braze.configuration.h(3), 6, (Object) null);
        try {
            f fVar = this.b;
            com.braze.enums.f fVar2 = fVar.j;
            fVar.j = com.braze.support.c.a(this.c, fVar.i);
            f fVar3 = this.b;
            com.braze.enums.f fVar4 = fVar3.j;
            if (fVar2 != fVar4) {
                fVar3.b.b(new o(fVar2, fVar4), o.class);
            }
            this.b.b();
        } catch (Exception e) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) c, BrazeLogger.Priority.E, (Throwable) e, false, (Function0) new com.braze.configuration.h(4), 4, (Object) null);
            f fVar5 = this.b;
            fVar5.a(fVar5.b, e);
        }
        this.d.finish();
        return Unit.a;
    }
}

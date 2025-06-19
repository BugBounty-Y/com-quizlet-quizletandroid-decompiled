package com.braze.managers;

import androidx.glance.appwidget.protobuf.Z;
import com.braze.Braze;
import com.braze.support.BrazeLogger;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;

/* renamed from: com.braze.managers.q, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1504q extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int a;
    public final /* synthetic */ r b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C1504q(r rVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.b = rVar;
    }

    public static final String a() {
        return "Requesting data flush on internal session close flush timer.";
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new C1504q(this.b, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return new C1504q(this.b, (kotlin.coroutines.h) obj2).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.a;
        if (i == 0) {
            Z.e(obj);
            long j = r.n;
            this.a = 1;
            if (kotlinx.coroutines.E.n(j, this) == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, r.m, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new K(28), 14, (Object) null);
        Braze.Companion.getInstance(this.b.a).requestImmediateDataFlush();
        return Unit.a;
    }
}

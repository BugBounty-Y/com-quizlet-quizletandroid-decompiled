package com.quizlet.humansecurity;

import android.app.Application;
import android.content.Context;
import androidx.glance.appwidget.protobuf.Z;
import com.google.firebase.perf.metrics.Trace;
import com.perimeterx.mobile_sdk.PerimeterX;
import com.perimeterx.mobile_sdk.PerimeterXDelegate;
import com.perimeterx.mobile_sdk.main.PXPolicy;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.u;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class a extends i implements Function2 {
    public final /* synthetic */ u j;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(u uVar, h hVar) {
        super(2, hVar);
        this.j = uVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new a(this.j, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((a) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        c cVar = (c) this.j.K.get();
        cVar.b.getClass();
        Trace traceC = Trace.c("HumanSecurityManager_init");
        Intrinsics.checkNotNullExpressionValue(traceC, "newTrace(...)");
        traceC.start();
        PXPolicy pXPolicy = new PXPolicy(null, null, null, false, false, null, false, 127, null);
        Context context = cVar.a;
        String string = context.getString(R.string.human_security_app_id);
        Intrinsics.checkNotNullExpressionValue(string, "getString(...)");
        pXPolicy.setDomains(c.d, string);
        try {
            try {
                PerimeterX perimeterX = PerimeterX.INSTANCE;
                Context applicationContext = context.getApplicationContext();
                Intrinsics.e(applicationContext, "null cannot be cast to non-null type android.app.Application");
                perimeterX.start((Application) applicationContext, string, (PerimeterXDelegate) null, pXPolicy);
                cVar.c = true;
            } catch (Exception e) {
                timber.log.c.a.f(e, "Failed to start Human Security SDK.", new Object[0]);
            }
            traceC.stop();
            return Unit.a;
        } catch (Throwable th) {
            traceC.stop();
            throw th;
        }
    }
}

package com.quizlet.quizletandroid.ui;

import android.content.Intent;
import androidx.camera.camera2.internal.c0;
import androidx.glance.appwidget.protobuf.Z;
import com.appsflyer.AppsFlyerLib;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class a extends i implements Function2 {
    public int j;
    public final /* synthetic */ RootActivity k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(RootActivity rootActivity, h hVar) {
        super(2, hVar);
        this.k = rootActivity;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new a(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((a) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws Throwable {
        Object objK;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            RootActivity rootActivity = this.k;
            c0 c0Var = rootActivity.g;
            if (c0Var == null) {
                Intrinsics.m("presenter");
                throw null;
            }
            Intent intent = rootActivity.getIntent();
            Intrinsics.checkNotNullExpressionValue(intent, "getIntent(...)");
            this.j = 1;
            if (intent.getData() == null) {
                objK = c0Var.k(this);
                if (objK != aVar) {
                    objK = Unit.a;
                }
            } else {
                com.quizlet.data.interactor.course.a listener = new com.quizlet.data.interactor.course.a(c0Var, 26);
                com.quizlet.analytics.marketing.appsflyer.b bVar = (com.quizlet.analytics.marketing.appsflyer.b) c0Var.d;
                Intrinsics.checkNotNullParameter(intent, "intent");
                Intrinsics.checkNotNullParameter(listener, "listener");
                AppsFlyerLib appsFlyerLib = AppsFlyerLib.getInstance();
                appsFlyerLib.subscribeForDeepLink(new com.google.firebase.tracing.a(3, bVar, listener));
                appsFlyerLib.performOnDeepLinking(intent, bVar.a);
                objK = Unit.a;
            }
            if (objK == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        return Unit.a;
    }
}

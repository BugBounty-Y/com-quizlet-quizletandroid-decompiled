package com.quizlet.quizletandroid;

import androidx.compose.foundation.text.input.internal.C0496b;
import androidx.glance.appwidget.protobuf.Z;
import com.appsflyer.AppsFlyerLib;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.flow.W;
import kotlinx.coroutines.flow.e0;

/* renamed from: com.quizlet.quizletandroid.b, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4594b extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ androidx.compose.runtime.internal.j k;
    public final /* synthetic */ QuizletApplication l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C4594b(androidx.compose.runtime.internal.j jVar, QuizletApplication quizletApplication, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = jVar;
        this.l = quizletApplication;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new C4594b(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C4594b) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            androidx.webkit.internal.p pVar = (androidx.webkit.internal.p) this.k.f;
            this.j = 1;
            AppsFlyerLib appsFlyerLib = AppsFlyerLib.getInstance();
            appsFlyerLib.setDebugLog(false);
            appsFlyerLib.init("ouQMsKHeNM2yE9fX3x3fhF", null, this.l);
            Object objB = e0.m(new com.quizlet.analytics.marketing.appsflyer.d((W) ((com.quizlet.usecase.a) pVar.b).a, 0)).b(new C0496b(appsFlyerLib, 9), this);
            if (objB != aVar) {
                objB = Unit.a;
            }
            if (objB != aVar) {
                objB = Unit.a;
            }
            if (objB == aVar) {
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

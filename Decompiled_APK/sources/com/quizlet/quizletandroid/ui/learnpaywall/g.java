package com.quizlet.quizletandroid.ui.learnpaywall;

import androidx.compose.ui.platform.C0958o;
import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.eventlogger.features.metering.StudyModeMeteringEventLogger;
import com.quizlet.studiablemodels.StudiableMeteringData;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class g extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ k k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public g(k kVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = kVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new g(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((g) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws Throwable {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            this.j = 1;
            k kVar = this.k;
            kVar.getClass();
            C0958o c0958o = new C0958o(3, kVar.b, StudyModeMeteringEventLogger.class, "logPaywallSecondaryAction", "logPaywallSecondaryAction(JLjava/lang/String;Lcom/quizlet/studiablemodels/StudiableMeteringData;)V", 0, 4);
            Long l = kVar.h;
            String str = kVar.i;
            StudiableMeteringData studiableMeteringData = kVar.j;
            if (l != null && str != null && studiableMeteringData != null) {
                c0958o.invoke(l, str, studiableMeteringData);
            }
            Object objEmit = kVar.d.emit(com.quizlet.upgrade.paywall.data.a.a, this);
            if (objEmit != aVar) {
                objEmit = Unit.a;
            }
            if (objEmit == aVar) {
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

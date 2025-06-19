package com.quizlet.upgrade.viewmodel;

import androidx.glance.appwidget.protobuf.Z;
import androidx.lifecycle.X;
import androidx.lifecycle.Y;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3730t6;
import com.quizlet.upgrade.data.I;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class l extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ n j;
    public final /* synthetic */ com.quizlet.data.model.billing.a k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public l(n nVar, com.quizlet.data.model.billing.a aVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.j = nVar;
        this.k = aVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new l(this.j, this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((l) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        com.onetrust.otpublishers.headless.UI.TVUI.datautils.d dVar = this.j.d;
        dVar.getClass();
        com.quizlet.data.model.billing.a subscriptionDetails = this.k;
        Intrinsics.checkNotNullParameter(subscriptionDetails, "subscriptionDetails");
        com.quizlet.billing.model.b bVarE = (com.quizlet.billing.model.b) dVar.g;
        if (bVarE == null) {
            bVarE = ((com.lyft.android.scissors.b) dVar.a).e();
        }
        boolean z = bVarE.h;
        X x = (X) dVar.f;
        if (z) {
            com.quizlet.billing.subscriptions.j targetSubscription = AbstractC3730t6.b(subscriptionDetails.a);
            x.j(new com.quizlet.upgrade.manager.b(new I(targetSubscription, (String) dVar.b)));
            com.quizlet.features.emailconfirmation.logging.a aVar2 = (com.quizlet.features.emailconfirmation.logging.a) dVar.c;
            Intrinsics.checkNotNullParameter(targetSubscription, "targetSubscription");
            aVar2.a.G("upgrade_launch_click", AbstractC3730t6.c(targetSubscription));
        } else if (bVarE.g) {
            ((Y) dVar.e).j(com.quizlet.upgrade.manager.f.a);
        } else {
            x.j(com.quizlet.upgrade.manager.a.a);
        }
        return Unit.a;
    }
}

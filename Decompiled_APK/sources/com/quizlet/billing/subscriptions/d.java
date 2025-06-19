package com.quizlet.billing.subscriptions;

import androidx.lifecycle.Y;
import com.android.billingclient.api.C1473b;
import com.android.billingclient.api.m;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3730t6;
import com.quizlet.billing.manager.BillingLibraryException;
import com.quizlet.upgrade.data.UpgradePackage;
import com.quizlet.upgrade.viewmodel.n;
import io.reactivex.rxjava3.subjects.r;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final /* synthetic */ class d implements io.reactivex.rxjava3.functions.d {
    public final /* synthetic */ int a;
    public final /* synthetic */ h b;

    public /* synthetic */ d(h hVar, int i) {
        this.a = i;
        this.b = hVar;
    }

    @Override // io.reactivex.rxjava3.functions.d
    public final void accept(Object obj) {
        switch (this.a) {
            case 0:
                h hVar = this.b;
                Throwable th = (Throwable) obj;
                hVar.getClass();
                if (!(th instanceof BillingLibraryException)) {
                    n nVar = hVar.e;
                    if (nVar != null) {
                        nVar.B(th);
                    }
                    timber.log.c.b(th);
                    return;
                }
                BillingLibraryException billingLibraryException = (BillingLibraryException) th;
                int i = billingLibraryException.a;
                if (i == 1) {
                    n nVar2 = hVar.e;
                    if (nVar2 != null) {
                        com.onetrust.otpublishers.headless.UI.TVUI.datautils.d dVar = nVar2.d;
                        ((com.quizlet.features.emailconfirmation.logging.a) dVar.c).a.D("upgrade_cancelled_by_user");
                        ((Y) dVar.e).j(com.quizlet.upgrade.manager.f.b);
                        return;
                    }
                    return;
                }
                if (i != 7) {
                    n nVar3 = hVar.e;
                    if (nVar3 != null) {
                        nVar3.B(billingLibraryException);
                        return;
                    }
                    return;
                }
                com.quizlet.billing.manager.f fVar = hVar.i;
                fVar.getClass();
                r rVar = new r();
                Intrinsics.checkNotNullExpressionValue(rVar, "create(...)");
                androidx.sqlite.db.a aVar = new androidx.sqlite.db.a();
                aVar.b = "subs";
                m mVar = new m(aVar);
                Intrinsics.checkNotNullExpressionValue(mVar, "build(...)");
                C1473b c1473b = fVar.e;
                if (c1473b == null) {
                    Intrinsics.m("billingClient");
                    throw null;
                }
                c1473b.g(mVar, new com.quizlet.billing.manager.a(fVar, rVar, 2));
                rVar.e(new f(hVar, 1)).i(new d(hVar, 2), new d(hVar, 0));
                return;
            case 1:
                n nVar4 = this.b.e;
                if (nVar4 != null) {
                    ((Y) nVar4.d.e).j(com.quizlet.upgrade.manager.g.a);
                    return;
                }
                return;
            default:
                com.quizlet.billing.model.c cVar = (com.quizlet.billing.model.c) obj;
                n nVar5 = this.b.e;
                if (nVar5 != null) {
                    j targetSubscription = cVar.c;
                    Intrinsics.checkNotNullParameter(targetSubscription, "subscriptionPackage");
                    com.onetrust.otpublishers.headless.UI.TVUI.datautils.d dVar2 = nVar5.d;
                    dVar2.getClass();
                    Intrinsics.checkNotNullParameter(targetSubscription, "subscriptionPackage");
                    com.quizlet.features.emailconfirmation.logging.a aVar2 = (com.quizlet.features.emailconfirmation.logging.a) dVar2.c;
                    Intrinsics.checkNotNullParameter(targetSubscription, "targetSubscription");
                    aVar2.a.G("upgrade_success", AbstractC3730t6.c(targetSubscription));
                    ((com.quizlet.infra.legacysyncengine.managers.d) ((com.lyft.android.scissors.b) dVar2.a).b).c();
                    ((Y) dVar2.e).j(new com.quizlet.upgrade.manager.h(new UpgradePackage(targetSubscription)));
                    return;
                }
                return;
        }
    }
}

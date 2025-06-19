package com.quizlet.billing.manager;

import android.content.Context;
import com.android.billingclient.api.C1473b;
import com.android.billingclient.api.k;
import com.android.billingclient.api.v;
import com.google.android.gms.measurement.internal.Z;
import com.quizlet.eventlogger.EventLogger;
import io.reactivex.rxjava3.subjects.r;
import java.util.List;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class f implements k {
    public static final String[] l = {"com.quizlet.quizletandroid.plus.autorenewing.1year", "com.quizlet.quizletandroid.plus.autorenewing.1year.bts2020", "com.quizlet.quizletandroid.plus.autorenewing.1year.trial3day", "com.quizlet.quizletandroid.plus.autorenewing.1year.trial7day", "com.quizlet.quizletandroid.plus.autorenewing.1year.trial7day.bts2020", "com.quizlet.quizletandroid.plus.autorenewing.1year.international.prices.2021", "com.quizlet.quizletandroid.plus.autorenewing.1year.trial7day.international.prices.2021", "com.quizlet.quizletandroid.go.autorenewing.1year.1199", "com.quizlet.quizletandroid.go.autorenewing.1year.bts2020", "com.quizlet.quizletandroid.go.autorenewing.1year.trial7day", "com.quizlet.quizletandroid.go.autorenewing.1year.trial7day.bts2020", "com.quizlet.quizletandroid.go.autorenewing.1year.international.prices.2021", "com.quizlet.quizletandroid.go.autorenewing.1year.trial7day.international.prices.2021", "com.quizlet.quizletandroid.teacher.autorenewing.1year.price2", "com.quizlet.quizletandroid.teacher.autorenewing.1year.bts2020", "com.quizlet.quizletandroid.teacher.autorenewing.1year.price2.trial30day", "com.quizlet.quizletandroid.teacher.autorenewing.1year.trial30day.bts2020", "com.quizlet.quizletandroid.teacher.autorenewing.1year.bts2021", "com.quizlet.quizletandroid.teacher.autorenewing.1year.trial30day.bts2021", "com.quizlet.quizletandroid.plus.autorenewing.1month"};
    public final com.quizlet.billing.client.provider.a a;
    public final com.quizlet.features.emailconfirmation.logging.a b;
    public final com.lyft.android.scissors.b c;
    public final com.quizlet.billing.model.a d;
    public C1473b e;
    public r f;
    public r g;
    public r h;
    public com.quizlet.billing.model.c i;
    public boolean j;
    public int k;

    public f(com.quizlet.billing.client.provider.a billingClientProvider, com.quizlet.features.emailconfirmation.logging.a billingEventLogger, com.lyft.android.scissors.b billingUserManager, com.quizlet.billing.model.a inventory) {
        Intrinsics.checkNotNullParameter(billingClientProvider, "billingClientProvider");
        Intrinsics.checkNotNullParameter(billingEventLogger, "billingEventLogger");
        Intrinsics.checkNotNullParameter(billingUserManager, "billingUserManager");
        Intrinsics.checkNotNullParameter(inventory, "inventory");
        this.a = billingClientProvider;
        this.b = billingEventLogger;
        this.c = billingUserManager;
        this.d = inventory;
        this.f = Z.f("create(...)");
        this.g = Z.f("create(...)");
        this.k = 2;
        Intrinsics.checkNotNullParameter(this, "purchasesUpdatedListener");
        billingClientProvider.b = this;
        b();
    }

    @Override // com.android.billingclient.api.k
    public final void a(com.android.billingclient.api.e result, List list) {
        Intrinsics.checkNotNullParameter(result, "result");
        int i = result.a;
        EventLogger eventLogger = this.b.a;
        if (i != 0 || list == null || list.isEmpty()) {
            BillingLibraryException error = new BillingLibraryException(result.a, null);
            r rVar = this.h;
            if (rVar != null) {
                rVar.onError(error);
            }
            if (result.a != 1) {
                Intrinsics.checkNotNullParameter(error, "error");
                eventLogger.E("upgrade_play_error", error.getMessage());
            }
        } else {
            eventLogger.D("upgrade_play_success");
            r rVar2 = this.h;
            if (rVar2 != null) {
                rVar2.onSuccess(CollectionsKt.L(list));
            }
        }
        this.j = false;
    }

    public final void b() {
        C1473b vVar;
        com.quizlet.billing.client.provider.a aVar = this.a;
        if (aVar.b == null) {
            throw new IllegalStateException("Purchase update listener HAS to be set before ret");
        }
        com.quizlet.shared.usecase.folderstudymaterials.b bVar = new com.quizlet.shared.usecase.folderstudymaterials.b(5);
        Intrinsics.checkNotNullExpressionValue(bVar, "build(...)");
        Context context = aVar.a;
        androidx.emoji2.text.f fVar = new androidx.emoji2.text.f(context);
        fVar.c = aVar;
        fVar.a = bVar;
        if (context == null) {
            throw new IllegalArgumentException("Please provide a valid Context.");
        }
        if (((k) fVar.c) == null) {
            throw new IllegalArgumentException("Please provide a valid listener for purchases updates.");
        }
        if (((com.quizlet.shared.usecase.folderstudymaterials.b) fVar.a) == null) {
            throw new IllegalArgumentException("Pending purchases for one-time products must be supported.");
        }
        ((com.quizlet.shared.usecase.folderstudymaterials.b) fVar.a).getClass();
        if (((k) fVar.c) != null) {
            com.quizlet.shared.usecase.folderstudymaterials.b bVar2 = (com.quizlet.shared.usecase.folderstudymaterials.b) fVar.a;
            k kVar = (k) fVar.c;
            vVar = fVar.a() ? new v(bVar2, context, kVar) : new C1473b(bVar2, context, kVar);
        } else {
            com.quizlet.shared.usecase.folderstudymaterials.b bVar3 = (com.quizlet.shared.usecase.folderstudymaterials.b) fVar.a;
            vVar = fVar.a() ? new v(bVar3, context) : new C1473b(bVar3, context);
        }
        Intrinsics.checkNotNullExpressionValue(vVar, "build(...)");
        this.e = vVar;
    }

    public final void c() {
        if (this.f.s() || this.f.r()) {
            return;
        }
        new io.reactivex.rxjava3.internal.operators.completable.c(new androidx.work.impl.utils.d(this, 8), 4).h(io.reactivex.rxjava3.schedulers.e.c).f(new com.quizlet.background.eventlogging.a(0), new d(timber.log.c.a, 0));
        this.f.i(new e(this, 0), io.reactivex.rxjava3.internal.functions.d.e);
    }
}

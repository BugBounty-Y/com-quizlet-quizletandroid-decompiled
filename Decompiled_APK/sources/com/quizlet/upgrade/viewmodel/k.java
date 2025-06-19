package com.quizlet.upgrade.viewmodel;

import androidx.lifecycle.Y;
import androidx.lifecycle.p0;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3778z6;
import com.quizlet.quizletandroid.R;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.collections.C4933y;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.E;

@Metadata
/* loaded from: classes3.dex */
public final class k extends com.quizlet.viewmodel.b {
    public final com.quizlet.data.repository.user.a c;
    public final com.quizlet.time.b d;
    public final Y e;
    public final Y f;
    public final Y g;
    public com.quizlet.upgrade.data.m h;
    public com.quizlet.upgrade.data.l i;

    public k(com.quizlet.data.repository.user.a getEligibleUpgradePlansUseCase, com.quizlet.features.emailconfirmation.logging.a billingEventLogger) {
        com.quizlet.time.b timeProvider = com.quizlet.time.b.a;
        Intrinsics.checkNotNullParameter(getEligibleUpgradePlansUseCase, "getEligibleUpgradePlansUseCase");
        Intrinsics.checkNotNullParameter(timeProvider, "timeProvider");
        Intrinsics.checkNotNullParameter(billingEventLogger, "billingEventLogger");
        this.c = getEligibleUpgradePlansUseCase;
        this.d = timeProvider;
        this.e = new Y();
        this.f = new Y();
        this.g = new Y();
        billingEventLogger.a.F("upgrade_see_plans_click", null);
        E.A(p0.j(this), null, null, new j(this, null), 3);
    }

    public static com.quizlet.upgrade.ui.widgets.a B(com.quizlet.data.model.billing.a aVar, com.quizlet.data.model.billing.b bVar) throws NumberFormatException {
        i iVar;
        com.quizlet.qutils.string.g fVar;
        com.quizlet.qutils.string.f fVar2;
        int iOrdinal = bVar.ordinal();
        if (iOrdinal == 0) {
            Object[] args = new Object[0];
            Intrinsics.checkNotNullParameter(args, "args");
            com.quizlet.qutils.string.f fVar3 = new com.quizlet.qutils.string.f(R.string.monthly_plan, C4933y.P(args));
            Object[] args2 = new Object[0];
            Intrinsics.checkNotNullParameter(args2, "args");
            com.quizlet.qutils.string.f fVar4 = new com.quizlet.qutils.string.f(R.string.monthly_frequency, C4933y.P(args2));
            Object[] args3 = new Object[0];
            Intrinsics.checkNotNullParameter(args3, "args");
            iVar = new i(fVar3, fVar4, new com.quizlet.qutils.string.f(R.string.monthly_plan_info, C4933y.P(args3)));
        } else {
            if (iOrdinal != 1) {
                throw new NoWhenBranchMatchedException();
            }
            if (aVar.a()) {
                int iA = AbstractC3778z6.a(aVar);
                Object[] args4 = {Integer.valueOf(iA)};
                Intrinsics.checkNotNullParameter(args4, "args");
                fVar = new com.quizlet.qutils.string.d(R.plurals.annual_plan_with_free_trial, iA, C4933y.P(args4));
            } else {
                Object[] args5 = new Object[0];
                Intrinsics.checkNotNullParameter(args5, "args");
                fVar = new com.quizlet.qutils.string.f(R.string.annual_plan, C4933y.P(args5));
            }
            Object[] args6 = new Object[0];
            Intrinsics.checkNotNullParameter(args6, "args");
            com.quizlet.qutils.string.f fVar5 = new com.quizlet.qutils.string.f(R.string.annual_frequency, C4933y.P(args6));
            if (aVar.a()) {
                Object[] args7 = new Object[0];
                Intrinsics.checkNotNullParameter(args7, "args");
                fVar2 = new com.quizlet.qutils.string.f(R.string.annual_plan_info_with_free_trial, C4933y.P(args7));
            } else {
                Object[] args8 = new Object[0];
                Intrinsics.checkNotNullParameter(args8, "args");
                fVar2 = new com.quizlet.qutils.string.f(R.string.annual_plan_info, C4933y.P(args8));
            }
            iVar = new i(fVar, fVar5, fVar2);
        }
        Intrinsics.checkNotNullParameter(aVar, "<this>");
        return new com.quizlet.upgrade.ui.widgets.a(iVar.a, new com.quizlet.upgrade.data.n(new com.quizlet.data.model.billing.c(aVar.b, aVar.c)), iVar.b, iVar.c, bVar == com.quizlet.data.model.billing.b.b);
    }
}

package com.quizlet.upgrade.viewmodel;

import androidx.lifecycle.X;
import androidx.lifecycle.Y;
import androidx.lifecycle.m0;
import androidx.lifecycle.p0;
import androidx.webkit.internal.p;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3778z6;
import com.quizlet.quizletandroid.R;
import com.quizlet.upgrade.data.D;
import java.util.Calendar;
import java.util.Date;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.collections.C4933y;
import kotlin.jvm.internal.Intrinsics;
import kotlin.u;
import kotlinx.coroutines.E;

@Metadata
/* loaded from: classes3.dex */
public final class h extends com.quizlet.viewmodel.b {
    public final m0 c;
    public final com.quizlet.quizletandroid.ui.activitycenter.models.a d;
    public final com.quizlet.data.repository.user.a e;
    public final com.quizlet.billing.model.a f;
    public final com.quizlet.time.b g;
    public final p h;
    public final com.google.firebase.crashlytics.internal.settings.b i;
    public final Y j;
    public final Y k;
    public final Y l;
    public final X m;
    public final X n;
    public final Y o;
    public final u p;

    public h(m0 savedStateHandle, com.lyft.android.scissors.b billingUserManager, com.quizlet.quizletandroid.ui.activitycenter.models.a getUpgradeFeaturesList, com.quizlet.data.repository.user.a getEligibleUpgradePlansUseCase, com.quizlet.billing.model.a billingInventory, p getManageSubscriptionLink, com.google.firebase.crashlytics.internal.settings.b getNotesEligibilityUseCase) {
        com.quizlet.time.b timeProvider = com.quizlet.time.b.a;
        Intrinsics.checkNotNullParameter(savedStateHandle, "savedStateHandle");
        Intrinsics.checkNotNullParameter(billingUserManager, "billingUserManager");
        Intrinsics.checkNotNullParameter(getUpgradeFeaturesList, "getUpgradeFeaturesList");
        Intrinsics.checkNotNullParameter(getEligibleUpgradePlansUseCase, "getEligibleUpgradePlansUseCase");
        Intrinsics.checkNotNullParameter(billingInventory, "billingInventory");
        Intrinsics.checkNotNullParameter(timeProvider, "timeProvider");
        Intrinsics.checkNotNullParameter(getManageSubscriptionLink, "getManageSubscriptionLink");
        Intrinsics.checkNotNullParameter(getNotesEligibilityUseCase, "getNotesEligibilityUseCase");
        this.c = savedStateHandle;
        this.d = getUpgradeFeaturesList;
        this.e = getEligibleUpgradePlansUseCase;
        this.f = billingInventory;
        this.g = timeProvider;
        this.h = getManageSubscriptionLink;
        this.i = getNotesEligibilityUseCase;
        this.j = new Y();
        this.k = new Y();
        this.l = new Y();
        this.m = new X(1);
        this.n = new X(1);
        this.o = new Y();
        this.p = kotlin.l.b(new com.quizlet.quizletandroid.ui.studymodes.assistant.settings.grading.a(this, 16));
        E.A(p0.j(this), null, null, new a(billingUserManager, this, null), 3);
    }

    /* JADX WARN: Code restructure failed: missing block: B:27:0x005c, code lost:
    
        if (r5.F(r6, r0) == r1) goto L28;
     */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0016  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object B(com.quizlet.upgrade.viewmodel.h r5, com.quizlet.billing.model.b r6, kotlin.coroutines.h r7) {
        /*
            r5.getClass()
            boolean r0 = r7 instanceof com.quizlet.upgrade.viewmodel.f
            if (r0 == 0) goto L16
            r0 = r7
            com.quizlet.upgrade.viewmodel.f r0 = (com.quizlet.upgrade.viewmodel.f) r0
            int r1 = r0.n
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L16
            int r1 = r1 - r2
            r0.n = r1
            goto L1b
        L16:
            com.quizlet.upgrade.viewmodel.f r0 = new com.quizlet.upgrade.viewmodel.f
            r0.<init>(r5, r7)
        L1b:
            java.lang.Object r7 = r0.l
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.n
            r3 = 2
            r4 = 1
            if (r2 == 0) goto L41
            if (r2 == r4) goto L39
            if (r2 != r3) goto L31
            com.quizlet.upgrade.viewmodel.h r5 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r7)     // Catch: java.lang.NumberFormatException -> L2f
            goto L6b
        L2f:
            r6 = move-exception
            goto L5f
        L31:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L39:
            com.quizlet.billing.model.b r6 = r0.k
            com.quizlet.upgrade.viewmodel.h r5 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r7)     // Catch: java.lang.NumberFormatException -> L2f
            goto L51
        L41:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            r0.j = r5     // Catch: java.lang.NumberFormatException -> L2f
            r0.k = r6     // Catch: java.lang.NumberFormatException -> L2f
            r0.n = r4     // Catch: java.lang.NumberFormatException -> L2f
            java.lang.Object r7 = r5.E(r6, r0)     // Catch: java.lang.NumberFormatException -> L2f
            if (r7 != r1) goto L51
            goto L5e
        L51:
            r0.j = r5     // Catch: java.lang.NumberFormatException -> L2f
            r7 = 0
            r0.k = r7     // Catch: java.lang.NumberFormatException -> L2f
            r0.n = r3     // Catch: java.lang.NumberFormatException -> L2f
            java.lang.Object r5 = r5.F(r6, r0)     // Catch: java.lang.NumberFormatException -> L2f
            if (r5 != r1) goto L6b
        L5e:
            return r1
        L5f:
            androidx.lifecycle.Y r5 = r5.o
            kotlin.Unit r7 = kotlin.Unit.a
            r5.j(r7)
            timber.log.a r5 = timber.log.c.a
            r5.e(r6)
        L6b:
            kotlin.Unit r5 = kotlin.Unit.a
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.upgrade.viewmodel.h.B(com.quizlet.upgrade.viewmodel.h, com.quizlet.billing.model.b, kotlin.coroutines.h):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object C(com.quizlet.billing.model.b r7, kotlin.coroutines.jvm.internal.c r8) {
        /*
            r6 = this;
            boolean r0 = r8 instanceof com.quizlet.upgrade.viewmodel.c
            if (r0 == 0) goto L13
            r0 = r8
            com.quizlet.upgrade.viewmodel.c r0 = (com.quizlet.upgrade.viewmodel.c) r0
            int r1 = r0.n
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.n = r1
            goto L18
        L13:
            com.quizlet.upgrade.viewmodel.c r0 = new com.quizlet.upgrade.viewmodel.c
            r0.<init>(r6, r8)
        L18:
            java.lang.Object r8 = r0.l
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.n
            r3 = 2
            r4 = 1
            if (r2 == 0) goto L34
            if (r2 != r4) goto L2c
            int r7 = r0.k
            com.quizlet.quizletandroid.ui.activitycenter.models.a r0 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L52
        L2c:
            java.lang.IllegalStateException r7 = new java.lang.IllegalStateException
            java.lang.String r8 = "call to 'resume' before 'invoke' with coroutine"
            r7.<init>(r8)
            throw r7
        L34:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            int r7 = r7.c
            if (r7 != r4) goto L3d
            r7 = r3
            goto L3e
        L3d:
            r7 = r4
        L3e:
            com.quizlet.quizletandroid.ui.activitycenter.models.a r8 = r6.d
            r0.j = r8
            r0.k = r7
            r0.n = r4
            com.google.firebase.crashlytics.internal.settings.b r2 = r6.i
            java.lang.Object r0 = r2.h(r0)
            if (r0 != r1) goto L4f
            return r1
        L4f:
            r5 = r0
            r0 = r8
            r8 = r5
        L52:
            java.lang.Boolean r8 = (java.lang.Boolean) r8
            boolean r8 = r8.booleanValue()
            r0.getClass()
            com.quizlet.upgrade.data.q r0 = com.quizlet.upgrade.data.p.a
            if (r7 == r4) goto L92
            if (r7 != r3) goto L84
            java.util.ArrayList r7 = new java.util.ArrayList
            r7.<init>()
            if (r8 == 0) goto L6b
            r7.add(r0)
        L6b:
            com.quizlet.upgrade.data.q r8 = com.quizlet.upgrade.data.p.f
            r7.add(r8)
            com.quizlet.upgrade.data.q r8 = com.quizlet.upgrade.data.p.g
            r7.add(r8)
            com.quizlet.upgrade.data.q r8 = com.quizlet.upgrade.data.p.h
            r7.add(r8)
            com.quizlet.upgrade.data.q r8 = com.quizlet.upgrade.data.p.i
            r7.add(r8)
            kotlinx.collections.immutable.b r7 = com.google.android.gms.internal.mlkit_vision_camera.AbstractC3409x1.i(r7)
            return r7
        L84:
            java.lang.IllegalArgumentException r8 = new java.lang.IllegalArgumentException
            java.lang.String r0 = "Not a valid UserUpgradeType("
            java.lang.String r1 = ") for retrieving features list"
            java.lang.String r7 = androidx.camera.camera2.internal.AbstractC0147y.c(r7, r0, r1)
            r8.<init>(r7)
            throw r8
        L92:
            java.util.ArrayList r7 = new java.util.ArrayList
            r7.<init>()
            if (r8 == 0) goto L9c
            r7.add(r0)
        L9c:
            com.quizlet.upgrade.data.q r8 = com.quizlet.upgrade.data.p.b
            r7.add(r8)
            com.quizlet.upgrade.data.q r8 = com.quizlet.upgrade.data.p.c
            r7.add(r8)
            com.quizlet.upgrade.data.q r8 = com.quizlet.upgrade.data.p.d
            r7.add(r8)
            com.quizlet.upgrade.data.q r8 = com.quizlet.upgrade.data.p.e
            r7.add(r8)
            kotlinx.collections.immutable.b r7 = com.google.android.gms.internal.mlkit_vision_camera.AbstractC3409x1.i(r7)
            return r7
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.upgrade.viewmodel.h.C(com.quizlet.billing.model.b, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public final D D(com.quizlet.data.model.billing.a aVar) throws NumberFormatException {
        com.quizlet.qutils.string.f fVarA;
        if (aVar == null || !aVar.a()) {
            return null;
        }
        int iA = AbstractC3778z6.a(aVar);
        Object[] args = {Integer.valueOf(iA)};
        Intrinsics.checkNotNullParameter(args, "args");
        com.quizlet.qutils.string.d dVar = new com.quizlet.qutils.string.d(R.plurals.header_free_trial_subheader, iA, C4933y.P(args));
        Object[] args2 = {Integer.valueOf(iA)};
        Intrinsics.checkNotNullParameter(args2, "args");
        com.quizlet.qutils.string.d dVar2 = new com.quizlet.qutils.string.d(R.plurals.header_free_trial_today_bullet_info, iA, C4933y.P(args2));
        this.g.getClass();
        Calendar calendarB = com.quizlet.time.b.b();
        Intrinsics.checkNotNullParameter(calendarB, "<this>");
        Calendar calendar = Calendar.getInstance();
        Intrinsics.checkNotNullExpressionValue(calendar, "getInstance(...)");
        calendar.setTime(calendarB.getTime());
        calendar.add(5, iA);
        Date date = calendar.getTime();
        Intrinsics.checkNotNullExpressionValue(date, "getTime(...)");
        Intrinsics.checkNotNullParameter("MMM d", "datePattern");
        Intrinsics.checkNotNullParameter(date, "date");
        com.quizlet.qutils.string.b bVar = new com.quizlet.qutils.string.b("MMM d", date);
        int iOrdinal = AbstractC3778z6.b(aVar).ordinal();
        if (iOrdinal == 0) {
            fVarA = com.quizlet.qutils.string.c.a(R.string.free_trial_period_month, new Object[0]);
        } else {
            if (iOrdinal != 1) {
                throw new NoWhenBranchMatchedException();
            }
            fVarA = com.quizlet.qutils.string.c.a(R.string.free_trial_period_year, new Object[0]);
        }
        return new D(dVar, dVar2, bVar, com.quizlet.qutils.string.c.a(R.string.header_free_trial_end_bullet_info, fVarA));
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0016  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object E(com.quizlet.billing.model.b r12, kotlin.coroutines.jvm.internal.c r13) {
        /*
            r11 = this;
            r0 = 0
            r1 = 2
            r2 = 1
            boolean r3 = r13 instanceof com.quizlet.upgrade.viewmodel.d
            if (r3 == 0) goto L16
            r3 = r13
            com.quizlet.upgrade.viewmodel.d r3 = (com.quizlet.upgrade.viewmodel.d) r3
            int r4 = r3.n
            r5 = -2147483648(0xffffffff80000000, float:-0.0)
            r6 = r4 & r5
            if (r6 == 0) goto L16
            int r4 = r4 - r5
            r3.n = r4
            goto L1b
        L16:
            com.quizlet.upgrade.viewmodel.d r3 = new com.quizlet.upgrade.viewmodel.d
            r3.<init>(r11, r13)
        L1b:
            java.lang.Object r13 = r3.l
            kotlin.coroutines.intrinsics.a r4 = kotlin.coroutines.intrinsics.a.a
            int r5 = r3.n
            if (r5 == 0) goto L36
            if (r5 != r2) goto L2e
            com.quizlet.billing.model.b r12 = r3.k
            com.quizlet.upgrade.viewmodel.h r3 = r3.j
            androidx.glance.appwidget.protobuf.Z.e(r13)
            r5 = r3
            goto L47
        L2e:
            java.lang.IllegalStateException r12 = new java.lang.IllegalStateException
            java.lang.String r13 = "call to 'resume' before 'invoke' with coroutine"
            r12.<init>(r13)
            throw r12
        L36:
            androidx.glance.appwidget.protobuf.Z.e(r13)
            r3.j = r11
            r3.k = r12
            r3.n = r2
            java.lang.Object r13 = r11.C(r12, r3)
            if (r13 != r4) goto L46
            return r4
        L46:
            r5 = r11
        L47:
            java.util.List r13 = (java.util.List) r13
            r5.getClass()
            int r12 = r12.c
            if (r12 != r2) goto L76
            com.quizlet.search.composables.E r3 = new com.quizlet.search.composables.E
            java.lang.String r8 = "onHelpCenterLinkClicked(Lcom/quizlet/upgrade/data/UpgradeHelpCenterType;)V"
            r9 = 0
            r4 = 1
            java.lang.Class<com.quizlet.upgrade.viewmodel.h> r6 = com.quizlet.upgrade.viewmodel.h.class
            java.lang.String r7 = "onHelpCenterLinkClicked"
            r10 = 10
            r3.<init>(r4, r5, r6, r7, r8, r9, r10)
            java.lang.String r12 = "onLinkClicked"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r3, r12)
            com.quizlet.upgrade.data.s r12 = new com.quizlet.upgrade.data.s
            r12.<init>(r3)
            com.quizlet.upgrade.data.v[] r1 = new com.quizlet.upgrade.data.v[r1]
            r1[r0] = r12
            com.quizlet.upgrade.data.t r12 = com.quizlet.upgrade.data.t.b
            r1[r2] = r12
            java.util.List r12 = kotlin.collections.B.j(r1)
            goto L84
        L76:
            com.quizlet.upgrade.data.v[] r12 = new com.quizlet.upgrade.data.v[r1]
            com.quizlet.upgrade.data.u r1 = com.quizlet.upgrade.data.u.b
            r12[r0] = r1
            com.quizlet.upgrade.data.t r0 = com.quizlet.upgrade.data.t.b
            r12[r2] = r0
            java.util.List r12 = kotlin.collections.B.j(r12)
        L84:
            androidx.lifecycle.Y r0 = r5.k
            com.quizlet.upgrade.data.C r1 = new com.quizlet.upgrade.data.C
            r1.<init>(r13, r12)
            r0.j(r1)
            kotlin.Unit r12 = kotlin.Unit.a
            return r12
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.upgrade.viewmodel.h.E(com.quizlet.billing.model.b, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0017  */
    /* JADX WARN: Type inference failed for: r12v0, types: [com.quizlet.upgrade.data.E] */
    /* JADX WARN: Type inference failed for: r12v2, types: [com.quizlet.upgrade.data.E] */
    /* JADX WARN: Type inference failed for: r6v2, types: [com.quizlet.upgrade.data.E] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object F(com.quizlet.billing.model.b r21, kotlin.coroutines.jvm.internal.c r22) throws java.lang.Throwable {
        /*
            Method dump skipped, instructions count: 684
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.upgrade.viewmodel.h.F(com.quizlet.billing.model.b, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }
}

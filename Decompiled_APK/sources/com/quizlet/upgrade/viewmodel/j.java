package com.quizlet.upgrade.viewmodel;

import androidx.glance.appwidget.protobuf.Z;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3778z6;
import com.quizlet.quizletandroid.R;
import com.quizlet.upgrade.data.C4837e;
import com.quizlet.upgrade.data.C4842j;
import com.quizlet.upgrade.data.H;
import com.quizlet.upgrade.data.J;
import com.quizlet.upgrade.data.p;
import java.util.Calendar;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import kotlin.Unit;
import kotlin.collections.C4933y;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.AbstractC5040y;
import kotlinx.coroutines.C;
import kotlinx.coroutines.E;

/* loaded from: classes3.dex */
public final class j extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ k k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public j(k kVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = kVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new j(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((j) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws Throwable {
        Object objJ;
        Object next;
        Object next2;
        com.quizlet.time.b bVar;
        com.quizlet.upgrade.data.m c4842j;
        com.quizlet.upgrade.ui.widgets.a aVar;
        kotlin.coroutines.intrinsics.a aVar2 = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        k kVar = this.k;
        if (i == 0) {
            Z.e(obj);
            com.quizlet.data.repository.user.a aVar3 = kVar.c;
            this.j = 1;
            aVar3.getClass();
            objJ = E.J((AbstractC5040y) aVar3.d, new C4837e(aVar3, false, null), this);
            if (objJ == aVar2) {
                return aVar2;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
            objJ = obj;
        }
        List list = (List) objJ;
        Iterator it2 = list.iterator();
        while (true) {
            if (!it2.hasNext()) {
                next = null;
                break;
            }
            next = it2.next();
            if (AbstractC3778z6.b((com.quizlet.data.model.billing.a) next) == com.quizlet.data.model.billing.b.b) {
                break;
            }
        }
        com.quizlet.data.model.billing.a aVar4 = (com.quizlet.data.model.billing.a) next;
        Iterator it3 = list.iterator();
        while (true) {
            if (!it3.hasNext()) {
                next2 = null;
                break;
            }
            next2 = it3.next();
            if (AbstractC3778z6.b((com.quizlet.data.model.billing.a) next2) == com.quizlet.data.model.billing.b.a) {
                break;
            }
        }
        com.quizlet.data.model.billing.a aVar5 = (com.quizlet.data.model.billing.a) next2;
        com.quizlet.time.b bVar2 = kVar.d;
        if (aVar4 == null) {
            bVar = bVar2;
        } else {
            if (aVar4.a()) {
                int iA = AbstractC3778z6.a(aVar4);
                bVar2.getClass();
                Calendar date = com.quizlet.time.b.b();
                Intrinsics.checkNotNullParameter(date, "date");
                com.quizlet.qutils.string.f fVarA = com.quizlet.qutils.string.c.a(R.string.timeline_first_task_heading, new Object[0]);
                Object[] args = {Integer.valueOf(iA)};
                Intrinsics.checkNotNullParameter(args, "args");
                bVar = bVar2;
                c4842j = new com.quizlet.upgrade.data.k(new J(new com.quizlet.upgrade.ui.widgets.b(R.drawable.ic_sys_unlock, fVarA, new com.quizlet.qutils.string.d(R.plurals.timeline_annual_with_free_trial_first_task_info, iA, C4933y.P(args)), true, true), new com.quizlet.upgrade.ui.widgets.b(R.drawable.ic_sys_bell, com.quizlet.qutils.string.c.a(R.string.timeline_annual_with_free_trial_second_task_heading, p.a(date, 5, iA - 3, "MMM d")), com.quizlet.qutils.string.c.a(R.string.timeline_annual_with_free_trial_second_task_info, new Object[0]), true, false), new com.quizlet.upgrade.ui.widgets.b(R.drawable.ic_sys_dollar, com.quizlet.qutils.string.c.a(R.string.timeline_annual_with_free_trial_third_task_heading, p.a(date, 5, iA, "MMM d")), com.quizlet.qutils.string.c.a(R.string.timeline_annual_with_free_trial_third_task_info, new Object[0]), false, false)), aVar4);
            } else {
                bVar = bVar2;
                bVar.getClass();
                Calendar date2 = com.quizlet.time.b.b();
                Intrinsics.checkNotNullParameter(date2, "date");
                Object[] args2 = new Object[0];
                Intrinsics.checkNotNullParameter(args2, "args");
                com.quizlet.qutils.string.f fVar = new com.quizlet.qutils.string.f(R.string.timeline_first_task_heading, C4933y.P(args2));
                Object[] args3 = new Object[0];
                Intrinsics.checkNotNullParameter(args3, "args");
                com.quizlet.upgrade.ui.widgets.b bVar3 = new com.quizlet.upgrade.ui.widgets.b(R.drawable.ic_sys_unlock, fVar, new com.quizlet.qutils.string.f(R.string.timeline_annual_first_task_info, C4933y.P(args3)), true, true);
                Intrinsics.checkNotNullParameter(date2, "<this>");
                Calendar calendar = Calendar.getInstance();
                Intrinsics.checkNotNullExpressionValue(calendar, "getInstance(...)");
                calendar.setTime(date2.getTime());
                calendar.add(1, 1);
                Date date3 = calendar.getTime();
                Intrinsics.checkNotNullExpressionValue(date3, "getTime(...)");
                Intrinsics.checkNotNullParameter("MMM d y", "datePattern");
                Intrinsics.checkNotNullParameter(date3, "date");
                Object[] args4 = {new com.quizlet.qutils.string.b("MMM d y", date3)};
                Intrinsics.checkNotNullParameter(args4, "args");
                com.quizlet.qutils.string.f fVar2 = new com.quizlet.qutils.string.f(R.string.timeline_annual_second_task_heading, C4933y.P(args4));
                Object[] args5 = new Object[0];
                Intrinsics.checkNotNullParameter(args5, "args");
                c4842j = new C4842j(new J(bVar3, new com.quizlet.upgrade.ui.widgets.b(R.drawable.ic_sys_refresh, fVar2, new com.quizlet.qutils.string.f(R.string.timeline_annual_second_task_info, C4933y.P(args5)), false, false), null), aVar4);
            }
            kVar.h = c4842j;
        }
        if (aVar5 == null) {
            aVar = null;
        } else {
            bVar.getClass();
            Calendar date4 = com.quizlet.time.b.b();
            Intrinsics.checkNotNullParameter(date4, "date");
            Object[] args6 = new Object[0];
            Intrinsics.checkNotNullParameter(args6, "args");
            com.quizlet.qutils.string.f fVar3 = new com.quizlet.qutils.string.f(R.string.timeline_first_task_heading, C4933y.P(args6));
            Object[] args7 = new Object[0];
            Intrinsics.checkNotNullParameter(args7, "args");
            com.quizlet.upgrade.ui.widgets.b bVar4 = new com.quizlet.upgrade.ui.widgets.b(R.drawable.ic_sys_unlock, fVar3, new com.quizlet.qutils.string.f(R.string.timeline_monthly_first_task_info, C4933y.P(args7)), true, true);
            Intrinsics.checkNotNullParameter(date4, "<this>");
            Calendar calendar2 = Calendar.getInstance();
            Intrinsics.checkNotNullExpressionValue(calendar2, "getInstance(...)");
            calendar2.setTime(date4.getTime());
            calendar2.add(2, 1);
            Date date5 = calendar2.getTime();
            Intrinsics.checkNotNullExpressionValue(date5, "getTime(...)");
            Intrinsics.checkNotNullParameter("MMM d", "datePattern");
            Intrinsics.checkNotNullParameter(date5, "date");
            Object[] args8 = {new com.quizlet.qutils.string.b("MMM d", date5)};
            Intrinsics.checkNotNullParameter(args8, "args");
            com.quizlet.qutils.string.f fVar4 = new com.quizlet.qutils.string.f(R.string.timeline_monthly_second_task_heading, C4933y.P(args8));
            Object[] args9 = new Object[0];
            Intrinsics.checkNotNullParameter(args9, "args");
            aVar = null;
            kVar.i = new com.quizlet.upgrade.data.l(new J(bVar4, new com.quizlet.upgrade.ui.widgets.b(R.drawable.ic_sys_refresh, fVar4, new com.quizlet.qutils.string.f(R.string.timeline_monthly_second_task_info, C4933y.P(args9)), false, false), null), aVar5);
        }
        kVar.e.j(new H(aVar4 != null ? k.B(aVar4, com.quizlet.data.model.billing.b.b) : aVar, aVar5 != null ? k.B(aVar5, com.quizlet.data.model.billing.b.a) : aVar));
        com.quizlet.upgrade.data.m mVar = kVar.h;
        if (mVar != null) {
            kVar.f.j(mVar);
        }
        if (aVar4 == null && aVar5 == null) {
            timber.log.c.a.q(new IllegalStateException("Billing should be disabled when inventory is empty"), "Subscription SKU details not found", new Object[0]);
            kVar.g.j(Unit.a);
        }
        return Unit.a;
    }
}

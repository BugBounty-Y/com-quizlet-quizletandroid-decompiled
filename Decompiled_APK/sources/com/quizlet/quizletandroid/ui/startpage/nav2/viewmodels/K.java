package com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels;

import androidx.glance.appwidget.protobuf.Z;
import androidx.lifecycle.p0;
import com.quizlet.data.model.EnumC4164s0;
import com.quizlet.eventlogger.features.home.HomeEventLog;
import com.quizlet.generated.enums.U;
import com.quizlet.quizletandroid.ui.globalnav.data.GlobalNavReroute;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.flow.d0;

/* loaded from: classes3.dex */
public final class K extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ GlobalNavReroute j;
    public final /* synthetic */ L k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public K(GlobalNavReroute globalNavReroute, L l, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.j = globalNavReroute;
        this.k = l;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new K(this.j, this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((K) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        L l = this.k;
        GlobalNavReroute globalNavReroute = this.j;
        if (globalNavReroute != null) {
            boolean zEquals = globalNavReroute.equals(GlobalNavReroute.Home.a);
            com.quizlet.quizletandroid.ui.startpage.nav2.logging.c cVar = l.h;
            d0 d0Var = l.p;
            if (zEquals) {
                cVar.getClass();
                cVar.a.l(HomeEventLog.Companion.b(HomeEventLog.b, "LoggedInHomepage", "bottom_nav", "clicked_home", U.CLICK.a(), null, 496));
                d0Var.h(C4746o.a);
            } else if (globalNavReroute instanceof GlobalNavReroute.Search) {
                kotlinx.coroutines.E.A(p0.j(l), null, null, new H(l, ((GlobalNavReroute.Search) globalNavReroute).a, null), 3);
            } else if (globalNavReroute.equals(GlobalNavReroute.CreateSet.a)) {
                d0Var.h(B.a);
            } else if (globalNavReroute.equals(GlobalNavReroute.ActivityCenter.a)) {
                io.reactivex.rxjava3.internal.observers.e eVarI = l.f.b(l.e).i(new com.quizlet.quizletandroid.ui.setpage.terms.c(l, 1), io.reactivex.rxjava3.internal.functions.d.e);
                Intrinsics.checkNotNullExpressionValue(eVarI, "subscribe(...)");
                Intrinsics.checkNotNullParameter(eVarI, "<this>");
                l.A(eVarI);
            } else if (globalNavReroute.equals(GlobalNavReroute.Account.a)) {
                com.quizlet.infra.legacysyncengine.managers.d dVar = l.d;
                long personId = dVar.e.getPersonId();
                d0Var.h(personId == dVar.e.getPersonId() ? C.a : new C4750t(personId));
                cVar.getClass();
                com.quizlet.quizletandroid.ui.startpage.nav2.logging.c.a(cVar, "clicked_profile");
            } else if (globalNavReroute.equals(GlobalNavReroute.ViewAllSets.a)) {
                l.B(EnumC4164s0.a);
            } else if (globalNavReroute.equals(GlobalNavReroute.ViewAllExplanations.a)) {
                l.B(EnumC4164s0.f);
            } else if (globalNavReroute.equals(GlobalNavReroute.EdgyDataCollection.a)) {
                L.C(l);
            } else if (globalNavReroute instanceof GlobalNavReroute.AchievementsProfile) {
                d0Var.h(C4740i.a);
            } else {
                if (!globalNavReroute.equals(GlobalNavReroute.Library.a)) {
                    throw new NoWhenBranchMatchedException();
                }
                l.B(null);
            }
        } else {
            l.q.h(Unit.a);
        }
        return Unit.a;
    }
}

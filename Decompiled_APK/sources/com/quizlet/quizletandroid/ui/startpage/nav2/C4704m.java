package com.quizlet.quizletandroid.ui.startpage.nav2;

import android.util.ArrayMap;
import android.widget.ProgressBar;
import androidx.recyclerview.widget.AbstractC1361d0;
import com.google.android.gms.internal.mlkit_vision_barcode.B7;
import com.quizlet.local.datastore.preferences.C4566c0;
import com.quizlet.quizletandroid.databinding.b0;
import com.quizlet.quizletandroid.ui.startpage.nav2.model.EnumC4720p;
import com.quizlet.quizletandroid.ui.startpage.nav2.model.InterfaceC4719o;
import io.reactivex.rxjava3.internal.operators.observable.C4887f;
import java.util.Iterator;
import java.util.List;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.quizletandroid.ui.startpage.nav2.m, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4704m extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ Object j;
    public final /* synthetic */ OldHomeFragment k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C4704m(OldHomeFragment oldHomeFragment, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = oldHomeFragment;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        C4704m c4704m = new C4704m(this.k, hVar);
        c4704m.j = obj;
        return c4704m;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C4704m) create((com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.r) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        androidx.glance.appwidget.protobuf.Z.e(obj);
        com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.r rVar = (com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.r) this.j;
        boolean z = rVar instanceof com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.n;
        OldHomeFragment snackbarCreator = this.k;
        kotlin.u uVar = snackbarCreator.X;
        kotlin.u uVar2 = snackbarCreator.K;
        kotlin.u uVar3 = snackbarCreator.J;
        kotlin.u uVar4 = snackbarCreator.H;
        if (z) {
            com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.n nVar = (com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.n) rVar;
            String str = OldHomeFragment.d1;
            ProgressBar homeProgressBar = ((b0) snackbarCreator.J()).d;
            Intrinsics.checkNotNullExpressionValue(homeProgressBar, "homeProgressBar");
            homeProgressBar.setVisibility(8);
            kotlin.u uVar5 = snackbarCreator.W;
            ((com.quizlet.quizletandroid.ui.startpage.nav2.adapters.d) uVar5.getValue()).f(kotlin.collections.A.b(new com.quizlet.quizletandroid.ui.startpage.nav2.model.r(nVar.a, nVar.b)));
            List listF = snackbarCreator.W().f();
            Intrinsics.checkNotNullExpressionValue(listF, "getAdapters(...)");
            Iterator it2 = listF.iterator();
            while (it2.hasNext()) {
                snackbarCreator.W().h((AbstractC1361d0) it2.next());
            }
            snackbarCreator.W().d((com.quizlet.quizletandroid.ui.startpage.nav2.adapters.d) uVar5.getValue());
            snackbarCreator.W().d((com.quizlet.quizletandroid.ui.startpage.nav2.adapters.o) uVar4.getValue());
            snackbarCreator.W().d((com.quizlet.quizletandroid.ui.startpage.nav2.adapters.f) uVar3.getValue());
            snackbarCreator.W().d((com.quizlet.quizletandroid.ui.startpage.nav2.adapters.p) uVar2.getValue());
            snackbarCreator.W().d((com.quizlet.quizletandroid.ui.startpage.nav2.adapters.m) uVar.getValue());
            snackbarCreator.X().setAdapter(snackbarCreator.W());
            snackbarCreator.X().setVisibility(0);
        } else if (rVar instanceof com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.m) {
            com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.v vVar = ((com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.m) rVar).a;
            String str2 = OldHomeFragment.d1;
            snackbarCreator.X().setAdapter(snackbarCreator.V());
            List listF2 = snackbarCreator.V().f();
            Intrinsics.checkNotNullExpressionValue(listF2, "getAdapters(...)");
            Iterator it3 = listF2.iterator();
            while (it3.hasNext()) {
                snackbarCreator.V().h((AbstractC1361d0) it3.next());
            }
            int i = 1;
            int i2 = 0;
            for (Object obj2 : vVar.a) {
                int i3 = i2 + 1;
                if (i2 < 0) {
                    kotlin.collections.B.p();
                    throw null;
                }
                InterfaceC4719o adapterType = (InterfaceC4719o) obj2;
                Intrinsics.checkNotNullParameter(adapterType, "adapterType");
                if (adapterType == EnumC4720p.b) {
                    snackbarCreator.T(i2, (com.quizlet.quizletandroid.ui.startpage.nav2.adapters.n) snackbarCreator.A.getValue());
                } else if (adapterType == EnumC4720p.a) {
                    snackbarCreator.T(i2, (com.quizlet.quizletandroid.ui.startpage.nav2.adapters.l) snackbarCreator.E.getValue());
                } else if (adapterType == EnumC4720p.c) {
                    snackbarCreator.T(i2, (com.quizlet.quizletandroid.ui.startpage.nav2.adapters.q) snackbarCreator.C.getValue());
                } else if (adapterType == EnumC4720p.d) {
                    snackbarCreator.T(i2, (com.quizlet.quizletandroid.ui.startpage.nav2.adapters.k) snackbarCreator.D.getValue());
                } else if (adapterType == EnumC4720p.e) {
                    snackbarCreator.T(i2, (com.quizlet.quizletandroid.ui.startpage.nav2.adapters.h) snackbarCreator.F.getValue());
                } else if (adapterType == EnumC4720p.f) {
                    snackbarCreator.T(i2, (com.quizlet.quizletandroid.ui.startpage.nav2.adapters.o) snackbarCreator.G.getValue());
                } else if (adapterType == EnumC4720p.g) {
                    Integer numValueOf = Integer.valueOf(i);
                    ArrayMap arrayMap = snackbarCreator.L;
                    Object obj3 = arrayMap.get(numValueOf);
                    Object obj4 = obj3;
                    if (obj3 == null) {
                        com.quizlet.quizletandroid.ui.startpage.nav2.adapters.o oVarU = snackbarCreator.U();
                        arrayMap.put(numValueOf, oVarU);
                        obj4 = oVarU;
                    }
                    snackbarCreator.T(i2, (com.quizlet.quizletandroid.ui.startpage.nav2.adapters.o) obj4);
                } else if (adapterType == EnumC4720p.h) {
                    snackbarCreator.T(i2, (com.quizlet.quizletandroid.ui.startpage.nav2.adapters.o) uVar4.getValue());
                } else if (adapterType == EnumC4720p.i) {
                    snackbarCreator.T(i2, (com.quizlet.quizletandroid.ui.startpage.nav2.adapters.j) snackbarCreator.B.getValue());
                } else if (adapterType == EnumC4720p.j) {
                    snackbarCreator.T(i2, (com.quizlet.quizletandroid.ui.startpage.nav2.adapters.e) snackbarCreator.M.getValue());
                } else if (adapterType == EnumC4720p.k) {
                    snackbarCreator.T(i2, (com.quizlet.quizletandroid.ui.startpage.nav2.adapters.m) uVar.getValue());
                } else if (adapterType == EnumC4720p.l) {
                    snackbarCreator.T(i2, (com.quizlet.quizletandroid.ui.startpage.nav2.adapters.p) snackbarCreator.I.getValue());
                } else if (adapterType == EnumC4720p.m) {
                    snackbarCreator.T(i2, (com.quizlet.quizletandroid.ui.startpage.nav2.adapters.f) uVar3.getValue());
                } else if (adapterType == EnumC4720p.n) {
                    snackbarCreator.T(i2, (com.quizlet.quizletandroid.ui.startpage.nav2.adapters.p) uVar2.getValue());
                }
                if (adapterType == EnumC4720p.g) {
                    i++;
                }
                i2 = i3;
            }
            ProgressBar homeProgressBar2 = ((b0) snackbarCreator.J()).d;
            Intrinsics.checkNotNullExpressionValue(homeProgressBar2, "homeProgressBar");
            homeProgressBar2.setVisibility(8);
            com.quizlet.offline.managers.b bVar = snackbarCreator.l;
            if (bVar == null) {
                Intrinsics.m("offlineStateManager");
                throw null;
            }
            C4700i addManagedSubscription = new C4700i(snackbarCreator, 3);
            com.quizlet.offline.managers.i iVar = (com.quizlet.offline.managers.i) bVar;
            Intrinsics.checkNotNullParameter(addManagedSubscription, "addManagedSubscription");
            Intrinsics.checkNotNullParameter(snackbarCreator, "snackbarCreator");
            io.reactivex.rxjava3.internal.operators.observable.C c = new io.reactivex.rxjava3.internal.operators.observable.C(new C4887f(((com.quizlet.remote.connectivity.b) iVar.b).a.a.q(com.quizlet.offline.managers.e.e), 1).w(iVar.e).s(iVar.c), new com.quizlet.analytics.marketing.e(addManagedSubscription, 19), io.reactivex.rxjava3.internal.functions.d.c);
            Intrinsics.checkNotNullExpressionValue(c, "doOnSubscribe(...)");
            addManagedSubscription.accept(B7.d(c, new C4566c0(19), null, new com.quizlet.features.folders.composables.J(iVar, snackbarCreator), 2));
            snackbarCreator.X().setVisibility(0);
        } else {
            if (!(rVar instanceof com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.q)) {
                throw new NoWhenBranchMatchedException();
            }
            String str3 = OldHomeFragment.d1;
            ProgressBar homeProgressBar3 = ((b0) snackbarCreator.J()).d;
            Intrinsics.checkNotNullExpressionValue(homeProgressBar3, "homeProgressBar");
            homeProgressBar3.setVisibility(0);
            snackbarCreator.X().setVisibility(8);
        }
        return Unit.a;
    }
}

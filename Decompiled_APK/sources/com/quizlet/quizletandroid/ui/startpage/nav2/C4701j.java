package com.quizlet.quizletandroid.ui.startpage.nav2;

import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.util.ArrayMap;
import android.view.View;
import androidx.lifecycle.p0;
import androidx.recyclerview.widget.AbstractC1381n0;
import androidx.recyclerview.widget.RecyclerView;
import androidx.swiperefreshlayout.widget.SwipeRefreshLayout;
import com.google.android.gms.internal.mlkit_vision_document_scanner.X5;
import com.quizlet.data.model.m2;
import com.quizlet.db.data.models.persisted.DBStudySet;
import com.quizlet.features.achievements.achievement.AchievementEarnedView;
import com.quizlet.features.notes.upload.UploadNotesActivity;
import com.quizlet.features.setpage.SetPageActivity;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.databinding.b0;
import com.quizlet.quizletandroid.ui.setcreation.activities.EditSetActivity;
import com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.C4740i;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.quizletandroid.ui.startpage.nav2.j, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final /* synthetic */ class C4701j implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ OldHomeFragment b;

    public /* synthetic */ C4701j(OldHomeFragment oldHomeFragment, int i) {
        this.a = i;
        this.b = oldHomeFragment;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) throws Exception {
        int i = 1;
        OldHomeFragment oldHomeFragment = this.b;
        switch (this.a) {
            case 0:
                com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.s sVar = (com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.s) obj;
                String str = OldHomeFragment.d1;
                if (sVar instanceof com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.f) {
                    DBStudySet dBStudySet = ((com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.f) sVar).a;
                    com.quizlet.features.setpage.utils.setpermissions.a aVar = oldHomeFragment.j;
                    if (aVar == null) {
                        Intrinsics.m("setPermissionsUtil");
                        throw null;
                    }
                    androidx.fragment.app.I activity = oldHomeFragment.getActivity();
                    Intrinsics.e(activity, "null cannot be cast to non-null type com.quizlet.baseui.base.BaseActivity");
                    io.reactivex.rxjava3.internal.operators.completable.a aVarA = ((com.quizlet.features.setpage.utils.setpermissions.f) aVar).a(dBStudySet, (com.quizlet.baseui.base.b) activity, new C4701j(oldHomeFragment, 20));
                    C4702k c4702k = new C4702k(oldHomeFragment, i);
                    com.quizlet.infra.legacysyncengine.net.request.g gVar = io.reactivex.rxjava3.internal.functions.d.d;
                    io.reactivex.rxjava3.internal.functions.b bVar = io.reactivex.rxjava3.internal.functions.d.c;
                    new io.reactivex.rxjava3.internal.operators.completable.i(aVarA, c4702k, gVar, bVar, bVar).e();
                } else if (Intrinsics.b(sVar, com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.e.a)) {
                    com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.L l = oldHomeFragment.Z;
                    if (l != null) {
                        kotlinx.coroutines.E.A(p0.j(l), null, null, new com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.H(l, null, null), 3);
                    }
                } else if (Intrinsics.b(sVar, com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.g.a)) {
                    int i2 = UploadNotesActivity.i;
                    Context contextRequireContext = oldHomeFragment.requireContext();
                    Intrinsics.checkNotNullExpressionValue(contextRequireContext, "requireContext(...)");
                    oldHomeFragment.requireContext().startActivity(com.google.android.gms.internal.mlkit_common.u.i(contextRequireContext, m2.b, null, null, null, 28));
                } else if (sVar instanceof com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.b) {
                    long j = ((com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.b) sVar).a;
                    Context context = oldHomeFragment.getContext();
                    int i3 = EditSetActivity.M;
                    Intent intent = new Intent(context, (Class<?>) EditSetActivity.class);
                    intent.putExtra("isFromHome", true);
                    intent.putExtra("editSetActivityId", j);
                    oldHomeFragment.startActivityForResult(intent, 201);
                } else if (sVar instanceof com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.w) {
                    com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.w wVar = (com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.w) sVar;
                    com.quizlet.offline.managers.j jVar = wVar.b;
                    com.quizlet.offline.managers.b bVar2 = oldHomeFragment.l;
                    if (bVar2 == null) {
                        Intrinsics.m("offlineStateManager");
                        throw null;
                    }
                    Context contextRequireContext2 = oldHomeFragment.requireContext();
                    Intrinsics.checkNotNullExpressionValue(contextRequireContext2, "requireContext(...)");
                    com.quizlet.features.setpage.e eVar = SetPageActivity.h1;
                    Context contextRequireContext3 = oldHomeFragment.requireContext();
                    Intrinsics.checkNotNullExpressionValue(contextRequireContext3, "requireContext(...)");
                    ((com.quizlet.offline.managers.i) bVar2).d(contextRequireContext2, jVar, com.quizlet.features.setpage.e.b(eVar, contextRequireContext3, wVar.a, null, null, null, null, false, null, 252), new C4700i(oldHomeFragment, 2));
                } else if (sVar instanceof com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.x) {
                    com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.x xVar = (com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.x) sVar;
                    long j2 = xVar.a;
                    RecommendationsActionOptionsFragment recommendationsActionOptionsFragment = new RecommendationsActionOptionsFragment();
                    Bundle bundle = new Bundle();
                    bundle.putLong("setID", j2);
                    Integer num = xVar.b;
                    if (num != null) {
                        bundle.putInt("recsSectionNumber", num.intValue());
                    }
                    recommendationsActionOptionsFragment.setArguments(bundle);
                    recommendationsActionOptionsFragment.O(oldHomeFragment.getChildFragmentManager(), RecommendationsActionOptionsFragment.D);
                } else {
                    boolean z = sVar instanceof com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.c;
                    com.quizlet.data.repository.folderwithcreatorinclass.e eVar2 = oldHomeFragment.v;
                    if (z) {
                        com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.L.C((com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.L) eVar2.getValue());
                    } else if (sVar instanceof com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.h) {
                        com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.L l2 = oldHomeFragment.Z;
                        if (l2 != null) {
                            l2.p.h(com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.v.a);
                        }
                    } else if (sVar instanceof com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.y) {
                        com.quizlet.quizletandroid.ui.webpages.a aVar2 = oldHomeFragment.q;
                        if (aVar2 == null) {
                            Intrinsics.m("webPageHelper");
                            throw null;
                        }
                        Context contextRequireContext4 = oldHomeFragment.requireContext();
                        Intrinsics.checkNotNullExpressionValue(contextRequireContext4, "requireContext(...)");
                        aVar2.c(contextRequireContext4, ((com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.y) sVar).a);
                    } else {
                        if (!(sVar instanceof com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.d)) {
                            throw new NoWhenBranchMatchedException();
                        }
                        ((com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.L) eVar2.getValue()).p.h(com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.C.a);
                    }
                }
                return Unit.a;
            case 1:
                String str2 = OldHomeFragment.d1;
                SwipeRefreshLayout homeSwipeRefresh = ((b0) oldHomeFragment.J()).f;
                Intrinsics.checkNotNullExpressionValue(homeSwipeRefresh, "homeSwipeRefresh");
                homeSwipeRefresh.setRefreshing(((Boolean) obj).booleanValue());
                return Unit.a;
            case 2:
                com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.t tVar = (com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.t) obj;
                String str3 = OldHomeFragment.d1;
                if (!(tVar instanceof com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.t)) {
                    throw new NoWhenBranchMatchedException();
                }
                int i4 = tVar.b;
                int i5 = tVar.a;
                if (i4 == 0) {
                    com.quizlet.quizletandroid.ui.startpage.nav2.adapters.o oVar = (com.quizlet.quizletandroid.ui.startpage.nav2.adapters.o) oldHomeFragment.G.getValue();
                    Integer numValueOf = Integer.valueOf(i4);
                    HashMap map = oVar.g;
                    if (map.containsKey(numValueOf)) {
                        ((com.quizlet.quizletandroid.ui.startpage.nav2.adapters.r) kotlin.collections.V.d(Integer.valueOf(i4), map)).notifyItemRemoved(i5);
                    }
                } else {
                    com.quizlet.quizletandroid.ui.startpage.nav2.adapters.o oVar2 = (com.quizlet.quizletandroid.ui.startpage.nav2.adapters.o) oldHomeFragment.L.get(Integer.valueOf(i4));
                    if (oVar2 != null) {
                        Integer numValueOf2 = Integer.valueOf(i4);
                        HashMap map2 = oVar2.g;
                        if (map2.containsKey(numValueOf2)) {
                            ((com.quizlet.quizletandroid.ui.startpage.nav2.adapters.r) kotlin.collections.V.d(Integer.valueOf(i4), map2)).notifyItemRemoved(i5);
                        }
                    }
                }
                return Unit.a;
            case 3:
                com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.a aVar3 = (com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.a) obj;
                String str4 = OldHomeFragment.d1;
                if (!(aVar3 instanceof com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.a)) {
                    throw new NoWhenBranchMatchedException();
                }
                AbstractC1381n0 layoutManager = oldHomeFragment.X().getLayoutManager();
                Intrinsics.d(layoutManager);
                View viewQ = layoutManager.q(aVar3.a);
                if (viewQ == null) {
                    timber.log.c.a.d("parent is null at position " + aVar3 + ".index", new Object[0]);
                } else {
                    RecyclerView recyclerView = (RecyclerView) viewQ.findViewById(R.id.horizontalHomeRecyclerView);
                    if (recyclerView == null) {
                        timber.log.c.a.d("no recyclerview found inside this parent " + viewQ, new Object[0]);
                    } else {
                        Y y = oldHomeFragment.t;
                        if (y == null) {
                            Intrinsics.m("viewModel");
                            throw null;
                        }
                        X5.b(recyclerView, y, true, aVar3.b, aVar3.c);
                    }
                }
                return Unit.a;
            case 4:
                com.quizlet.features.achievements.notification.c cVar = (com.quizlet.features.achievements.notification.c) obj;
                String str5 = OldHomeFragment.d1;
                if (cVar instanceof com.quizlet.features.achievements.notification.a) {
                    AchievementEarnedView achievementToast = ((b0) oldHomeFragment.J()).b;
                    Intrinsics.checkNotNullExpressionValue(achievementToast, "achievementToast");
                    achievementToast.g(((com.quizlet.features.achievements.notification.a) cVar).a);
                }
                return Unit.a;
            case 5:
                String str6 = OldHomeFragment.d1;
                ((com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.L) oldHomeFragment.v.getValue()).p.h(C4740i.a);
                return Unit.a;
            case 6:
                String str7 = OldHomeFragment.d1;
                ((com.quizlet.quizletandroid.ui.startpage.nav2.adapters.n) oldHomeFragment.A.getValue()).f(((com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.k) obj).a);
                return Unit.a;
            case 7:
                String str8 = OldHomeFragment.d1;
                ((com.quizlet.quizletandroid.ui.startpage.nav2.adapters.m) oldHomeFragment.X.getValue()).f(((com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.j) obj).a);
                return Unit.a;
            case 8:
                String str9 = OldHomeFragment.d1;
                ((com.quizlet.quizletandroid.ui.startpage.nav2.adapters.p) oldHomeFragment.I.getValue()).f(((com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.l) obj).a);
                return Unit.a;
            case 9:
                String str10 = OldHomeFragment.d1;
                ((com.quizlet.quizletandroid.ui.startpage.nav2.adapters.f) oldHomeFragment.J.getValue()).f(((com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.l) obj).a);
                return Unit.a;
            case 10:
                String str11 = OldHomeFragment.d1;
                ((com.quizlet.quizletandroid.ui.startpage.nav2.adapters.p) oldHomeFragment.K.getValue()).f(((com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.l) obj).a);
                return Unit.a;
            case 11:
                String str12 = OldHomeFragment.d1;
                ((com.quizlet.quizletandroid.ui.startpage.nav2.adapters.j) oldHomeFragment.B.getValue()).f(((com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.l) obj).a);
                return Unit.a;
            case 12:
                String str13 = OldHomeFragment.d1;
                ((com.quizlet.quizletandroid.ui.startpage.nav2.adapters.q) oldHomeFragment.C.getValue()).f(((com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.l) obj).a);
                return Unit.a;
            case 13:
                String str14 = OldHomeFragment.d1;
                ((com.quizlet.quizletandroid.ui.startpage.nav2.adapters.l) oldHomeFragment.E.getValue()).f(((com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.l) obj).a);
                return Unit.a;
            case 14:
                String str15 = OldHomeFragment.d1;
                ((com.quizlet.quizletandroid.ui.startpage.nav2.adapters.k) oldHomeFragment.D.getValue()).f(((com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.l) obj).a);
                return Unit.a;
            case 15:
                String str16 = OldHomeFragment.d1;
                ((com.quizlet.quizletandroid.ui.startpage.nav2.adapters.h) oldHomeFragment.F.getValue()).f(((com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.l) obj).a);
                return Unit.a;
            case 16:
                String str17 = OldHomeFragment.d1;
                ((com.quizlet.quizletandroid.ui.startpage.nav2.adapters.o) oldHomeFragment.G.getValue()).f(((com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.l) obj).a);
                return Unit.a;
            case 17:
                com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.u uVar = (com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.u) obj;
                String str18 = OldHomeFragment.d1;
                if (uVar.a.isEmpty()) {
                    Iterator it2 = oldHomeFragment.L.entrySet().iterator();
                    while (it2.hasNext()) {
                        ((com.quizlet.quizletandroid.ui.startpage.nav2.adapters.o) ((Map.Entry) it2.next()).getValue()).f(kotlin.collections.K.a);
                    }
                } else {
                    Map map3 = uVar.a;
                    Iterator it3 = map3.keySet().iterator();
                    while (it3.hasNext()) {
                        int iIntValue = ((Number) it3.next()).intValue();
                        ArrayMap arrayMap = oldHomeFragment.L;
                        Integer numValueOf3 = Integer.valueOf(iIntValue);
                        Object objU = arrayMap.get(numValueOf3);
                        if (objU == null) {
                            objU = oldHomeFragment.U();
                            arrayMap.put(numValueOf3, objU);
                        }
                        ((com.quizlet.quizletandroid.ui.startpage.nav2.adapters.o) objU).f((List) map3.get(Integer.valueOf(iIntValue)));
                    }
                }
                return Unit.a;
            case 18:
                String str19 = OldHomeFragment.d1;
                ((com.quizlet.quizletandroid.ui.startpage.nav2.adapters.o) oldHomeFragment.H.getValue()).f(((com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.l) obj).a);
                return Unit.a;
            case 19:
                String str20 = OldHomeFragment.d1;
                ((com.quizlet.quizletandroid.ui.startpage.nav2.adapters.e) oldHomeFragment.M.getValue()).f(((com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.i) obj).a);
                return Unit.a;
            default:
                DBStudySet set = (DBStudySet) obj;
                String str21 = OldHomeFragment.d1;
                Intrinsics.checkNotNullParameter(set, "set");
                com.quizlet.features.setpage.e eVar3 = SetPageActivity.h1;
                Context contextRequireContext5 = oldHomeFragment.requireContext();
                Intrinsics.checkNotNullExpressionValue(contextRequireContext5, "requireContext(...)");
                oldHomeFragment.startActivityForResult(com.quizlet.features.setpage.e.c(24, set.getSetId(), contextRequireContext5), 201);
                return Unit.a;
        }
    }
}

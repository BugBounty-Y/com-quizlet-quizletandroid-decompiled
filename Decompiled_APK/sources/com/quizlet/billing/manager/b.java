package com.quizlet.billing.manager;

import android.content.Context;
import android.view.View;
import android.widget.TextView;
import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.camera.core.AbstractC0151c;
import androidx.compose.ui.platform.C0960p;
import androidx.fragment.app.AbstractC1136h0;
import androidx.lifecycle.Y;
import androidx.lifecycle.p0;
import androidx.recyclerview.widget.RecyclerView;
import androidx.work.A;
import androidx.work.C1425f;
import androidx.work.EnumC1441o;
import androidx.work.G;
import androidx.work.impl.r;
import com.android.billingclient.api.g;
import com.android.billingclient.api.h;
import com.android.billingclient.api.i;
import com.android.billingclient.api.j;
import com.comscore.streaming.EventType;
import com.google.android.datatransport.cct.internal.s;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3125d6;
import com.google.android.gms.measurement.internal.N;
import com.onetrust.otpublishers.headless.UI.fragment.q;
import com.quizlet.background.progress.ProgressResetSyncWorker;
import com.quizlet.data.model.C4127f1;
import com.quizlet.data.model.C4151n1;
import com.quizlet.data.model.InterfaceC4176w0;
import com.quizlet.data.model.U1;
import com.quizlet.data.model.k2;
import com.quizlet.db.data.caches.UserInfoCache;
import com.quizlet.db.data.models.persisted.DBStudySet;
import com.quizlet.db.data.models.persisted.DBTerm;
import com.quizlet.db.data.models.persisted.DBUser;
import com.quizlet.features.infra.studysetting.data.TestStudyModeConfig;
import com.quizlet.features.match.data.D;
import com.quizlet.features.match.data.E;
import com.quizlet.features.setpage.viewmodel.P;
import com.quizlet.generated.enums.O1;
import com.quizlet.login.oldlogin.o;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.databinding.C4602f;
import com.quizlet.quizletandroid.ui.group.classcontent.viewmodel.k;
import com.quizlet.quizletandroid.ui.joincontenttofolder.l;
import com.quizlet.quizletandroid.ui.joincontenttofolder.m;
import com.quizlet.quizletandroid.ui.setcreation.activities.EditSetPermissionSelectionActivity;
import com.quizlet.quizletandroid.ui.setcreation.activities.n;
import com.quizlet.quizletandroid.ui.setcreation.activities.p;
import com.quizlet.quizletandroid.ui.setcreation.fragments.EditSetFragment;
import com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.w;
import com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.C4756b;
import com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.B;
import com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.F;
import com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.z;
import com.quizlet.remote.exceptions.NetException;
import com.quizlet.studiablemodels.StudiableQuestion;
import com.quizlet.studiablemodels.diagrams.DiagramData;
import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.concurrent.TimeoutException;
import kotlin.Pair;
import kotlin.Unit;
import kotlin.collections.C;
import kotlin.collections.C4933y;
import kotlin.collections.CollectionsKt;
import kotlin.collections.U;
import kotlin.jvm.internal.Intrinsics;
import retrofit2.HttpException;

/* loaded from: classes2.dex */
public final class b implements io.reactivex.rxjava3.functions.d {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ Object c;

    public /* synthetic */ b(int i, Object obj, Object obj2) {
        this.a = i;
        this.b = obj;
        this.c = obj2;
    }

    @Override // io.reactivex.rxjava3.functions.d
    public final void accept(Object obj) throws Exception {
        Object next;
        h hVar;
        NetException netExceptionJ;
        com.quizlet.quizletandroid.sessionhelpers.a aVar;
        D d;
        switch (this.a) {
            case 0:
                com.quizlet.billing.model.b billingUser = (com.quizlet.billing.model.b) obj;
                Intrinsics.checkNotNullParameter(billingUser, "billingUser");
                ArrayList availableProductDetails = (ArrayList) this.b;
                ArrayList availableSubs = new ArrayList(C.q(availableProductDetails, 10));
                Iterator it2 = availableProductDetails.iterator();
                while (it2.hasNext()) {
                    j jVar = (j) it2.next();
                    Intrinsics.d(jVar);
                    boolean z = billingUser.e;
                    Intrinsics.checkNotNullParameter(jVar, "<this>");
                    String str = jVar.c;
                    Intrinsics.checkNotNullExpressionValue(str, "getProductId(...)");
                    int length = str.length();
                    String str2 = jVar.f;
                    if (length == 0) {
                        throw new IllegalArgumentException(android.support.v4.media.session.a.B("Subscription Details requires non-empty productId (", str2, ")"));
                    }
                    String str3 = jVar.d;
                    if (!Intrinsics.b(str3, "subs")) {
                        throw new IllegalArgumentException(android.support.v4.media.session.a.t(AbstractC0147y.h("Non-subscription product type (", str3, ") can't be converted to SubscriptionDetails for ", str2, " ("), str, ")"));
                    }
                    Intrinsics.checkNotNullParameter(jVar, "<this>");
                    String str4 = null;
                    ArrayList arrayList = jVar.i;
                    i iVar = arrayList != null ? (i) CollectionsKt.firstOrNull(arrayList) : null;
                    ArrayList arrayList2 = (iVar == null || (hVar = iVar.b) == null) ? null : hVar.a;
                    if (arrayList2 == null || arrayList2.isEmpty()) {
                        StringBuilder sbH = AbstractC0147y.h("Subscription Details requires non-empty pricingPhases for ", str2, " (", str, ") with subscriptionOfferDetails: ");
                        sbH.append(arrayList);
                        throw new IllegalArgumentException(sbH.toString());
                    }
                    g gVar = (g) CollectionsKt.U(arrayList2);
                    if (arrayList2.size() > 1) {
                        Iterator it3 = arrayList2.iterator();
                        while (true) {
                            if (it3.hasNext()) {
                                next = it3.next();
                                if (((g) next).a == 0) {
                                }
                            } else {
                                next = null;
                            }
                        }
                        g gVar2 = (g) next;
                        if (gVar2 != null) {
                            str4 = gVar2.c;
                        }
                    }
                    String str5 = jVar.c;
                    Intrinsics.checkNotNullExpressionValue(str5, "getProductId(...)");
                    long j = gVar.a;
                    String str6 = gVar.b;
                    Intrinsics.checkNotNullExpressionValue(str6, "getPriceCurrencyCode(...)");
                    String str7 = jVar.f;
                    Intrinsics.checkNotNullExpressionValue(str7, "getName(...)");
                    String str8 = gVar.c;
                    Intrinsics.checkNotNullExpressionValue(str8, "getBillingPeriod(...)");
                    availableSubs.add(new com.quizlet.data.model.billing.a(str5, j, str6, str7, str8, str4, z));
                }
                f fVar = (f) this.c;
                com.quizlet.billing.model.a aVar2 = fVar.d;
                aVar2.getClass();
                Intrinsics.checkNotNullParameter(availableSubs, "availableSubs");
                LinkedHashMap linkedHashMap = aVar2.a;
                linkedHashMap.clear();
                int iA = U.a(C.q(availableSubs, 10));
                if (iA < 16) {
                    iA = 16;
                }
                LinkedHashMap linkedHashMap2 = new LinkedHashMap(iA);
                Iterator it4 = availableSubs.iterator();
                while (it4.hasNext()) {
                    Object next2 = it4.next();
                    linkedHashMap2.put(((com.quizlet.data.model.billing.a) next2).a, next2);
                }
                linkedHashMap.putAll(linkedHashMap2);
                com.quizlet.billing.model.a aVar3 = fVar.d;
                aVar3.getClass();
                Intrinsics.checkNotNullParameter(availableProductDetails, "availableProductDetails");
                LinkedHashMap linkedHashMap3 = aVar3.b;
                linkedHashMap3.clear();
                int iA2 = U.a(C.q(availableProductDetails, 10));
                LinkedHashMap linkedHashMap4 = new LinkedHashMap(iA2 >= 16 ? iA2 : 16);
                Iterator it5 = availableProductDetails.iterator();
                while (it5.hasNext()) {
                    Object next3 = it5.next();
                    linkedHashMap4.put(((j) next3).c, next3);
                }
                linkedHashMap3.putAll(linkedHashMap4);
                return;
            case 1:
                Throwable it6 = (Throwable) obj;
                Intrinsics.checkNotNullParameter(it6, "it");
                com.google.mlkit.vision.documentscanner.internal.c cVar = (com.google.mlkit.vision.documentscanner.internal.c) ((com.quizlet.data.repository.set.f) this.b).d;
                C4127f1 progressReset = (C4127f1) this.c;
                Intrinsics.checkNotNullParameter(progressReset, "progressReset");
                String str9 = "progress_reset_sync_" + new com.quizlet.data.repository.progress.c(progressReset.a, progressReset.b, progressReset.c);
                EnumC1441o enumC1441o = EnumC1441o.a;
                Intrinsics.checkNotNullParameter(ProgressResetSyncWorker.class, "workerClass");
                androidx.work.C c = new androidx.work.C(ProgressResetSyncWorker.class);
                Intrinsics.checkNotNullParameter(progressReset, "progressReset");
                Pair[] pairArr = {new Pair("personId", Long.valueOf(progressReset.a)), new Pair("setId", Long.valueOf(progressReset.b))};
                G g = new G();
                for (int i = 0; i < 2; i++) {
                    Pair pair = pairArr[i];
                    g.b(pair.b, (String) pair.a);
                }
                androidx.work.C c2 = (androidx.work.C) c.k(g.a());
                LinkedHashSet linkedHashSet = new LinkedHashSet();
                A networkType = A.b;
                Intrinsics.checkNotNullParameter(networkType, "networkType");
                ((r) cVar.b).a(str9, enumC1441o, (androidx.work.D) ((androidx.work.C) c2.j(new C1425f(new androidx.work.impl.utils.g(null), networkType, false, false, false, false, -1L, -1L, CollectionsKt.A0(linkedHashSet)))).a()).c();
                return;
            case 2:
                com.quizlet.data.model.U exercise = (com.quizlet.data.model.U) obj;
                Intrinsics.checkNotNullParameter(exercise, "exercise");
                ((LinkedHashMap) ((com.quizlet.data.repository.explanations.exercise.b) this.b).d).put((String) this.c, exercise);
                return;
            case 3:
                C4151n1 question = (C4151n1) obj;
                Intrinsics.checkNotNullParameter(question, "question");
                ((LinkedHashMap) ((com.quizlet.data.repository.explanations.question.a) this.b).d).put((String) this.c, question);
                return;
            case 4:
                k2 textbookWithMetering = (k2) obj;
                Intrinsics.checkNotNullParameter(textbookWithMetering, "textbookWithMetering");
                ((LinkedHashMap) ((com.quizlet.data.repository.explanations.textbook.a) this.b).d).put((String) this.c, textbookWithMetering);
                return;
            case 5:
                Throwable error = (Throwable) obj;
                Intrinsics.checkNotNullParameter(error, "error");
                ((com.quizlet.features.setpage.utils.setpermissions.f) this.b).getClass();
                timber.log.a aVar4 = timber.log.c.a;
                com.quizlet.baseui.base.b bVar = (com.quizlet.baseui.base.b) this.c;
                aVar4.q(error, "Top level exception thrown: %s", bVar.getString(R.string.could_not_sync_password));
                AbstractC3125d6.d(bVar, bVar.getString(R.string.could_not_sync_password));
                if (!(error instanceof HttpException) || (netExceptionJ = q.j(((HttpException) error).a)) == null) {
                    return;
                }
                bVar.I(false);
                aVar4.q(netExceptionJ, "Top level netException thrown: %s", bVar.getString(R.string.could_not_sync_password));
                AbstractC3125d6.d(bVar, bVar.getString(R.string.could_not_handle));
                return;
            case 6:
                DBStudySet it7 = (DBStudySet) obj;
                Intrinsics.checkNotNullParameter(it7, "it");
                P p = (P) this.c;
                Y y = p.h1;
                boolean zD = p.l.d(p.D());
                DBStudySet dBStudySet = p.F1;
                if (dBStudySet != null) {
                    y.j(new com.quizlet.features.setpage.studypreview.data.b((ArrayList) this.b, zD, dBStudySet.getLocalId()));
                    return;
                } else {
                    Intrinsics.m("set");
                    throw null;
                }
            case 7:
                DBStudySet it8 = (DBStudySet) obj;
                Intrinsics.checkNotNullParameter(it8, "it");
                ((P) this.b).n1.j(new com.quizlet.features.setpage.shareset.a(it8.getWebUrl(), (U1) this.c));
                return;
            case 8:
                com.quizlet.login.authentication.data.i response = (com.quizlet.login.authentication.data.i) obj;
                Intrinsics.checkNotNullParameter(response, "response");
                ((o) this.b).B(response, (String) this.c);
                return;
            case 9:
                com.quizlet.quizletandroid.data.management.b bVar2 = (com.quizlet.quizletandroid.data.management.b) obj;
                io.reactivex.rxjava3.subjects.b bVar3 = bVar2.a;
                Object obj2 = bVar3.a.get();
                Object obj3 = io.reactivex.rxjava3.subjects.b.e;
                boolean z2 = obj2 == obj3 && bVar3.b == null;
                io.reactivex.rxjava3.subjects.b bVar4 = bVar2.a;
                if (!z2 || bVar4.a.get() != obj3 || bVar4.b == null) {
                    bVar4.onComplete();
                }
                com.quizlet.infra.legacysyncengine.net.listeners.d dVar = (com.quizlet.infra.legacysyncengine.net.listeners.d) ((s) this.b).g;
                dVar.c.computeIfPresent(dVar.b.convertStaleLocalIds((com.quizlet.infra.legacysyncengine.orm.query.a) this.c), new com.quizlet.infra.legacysyncengine.net.listeners.a(dVar, bVar2.b, 1));
                return;
            case 10:
                Unit it9 = (Unit) obj;
                Intrinsics.checkNotNullParameter(it9, "it");
                ((com.quizlet.quizletandroid.ui.common.adapter.f) this.b).d((DiagramData) this.c);
                return;
            case 11:
                com.quizlet.offline.managers.j launchBehavior = (com.quizlet.offline.managers.j) obj;
                Intrinsics.checkNotNullParameter(launchBehavior, "launchBehavior");
                com.quizlet.offline.managers.j jVar2 = com.quizlet.offline.managers.j.a;
                com.quizlet.quizletandroid.ui.group.classcontent.models.d dVar2 = (com.quizlet.quizletandroid.ui.group.classcontent.models.d) this.c;
                com.quizlet.quizletandroid.ui.group.classcontent.viewmodel.a aVar5 = (com.quizlet.quizletandroid.ui.group.classcontent.viewmodel.a) this.b;
                if (launchBehavior == jVar2) {
                    aVar5.m.j(new k(dVar2.a));
                    return;
                } else {
                    aVar5.n.j(new com.quizlet.quizletandroid.ui.group.classcontent.viewmodel.c(dVar2.a, launchBehavior));
                    return;
                }
            case 12:
                View it10 = (View) obj;
                Intrinsics.checkNotNullParameter(it10, "it");
                m mVar = (m) this.b;
                com.quizlet.quizletandroid.ui.joincontenttofolder.models.b bVar5 = ((l) this.c).d;
                if (bVar5 != null) {
                    mVar.c.invoke(Long.valueOf(bVar5.a.a()));
                    return;
                } else {
                    Intrinsics.m("folderItem");
                    throw null;
                }
            case 13:
                Boolean isEnabled = (Boolean) obj;
                Intrinsics.checkNotNullParameter(isEnabled, "isEnabled");
                com.quizlet.quizletandroid.util.j jVar3 = com.quizlet.quizletandroid.util.j.c;
                EditSetPermissionSelectionActivity editSetPermissionSelectionActivity = (EditSetPermissionSelectionActivity) this.c;
                n nVarB0 = EditSetPermissionSelectionActivity.b0(editSetPermissionSelectionActivity, jVar3);
                n nVarB02 = EditSetPermissionSelectionActivity.b0(editSetPermissionSelectionActivity, com.quizlet.quizletandroid.util.j.b);
                n nVarB03 = EditSetPermissionSelectionActivity.b0(editSetPermissionSelectionActivity, com.quizlet.quizletandroid.util.j.a);
                boolean z3 = editSetPermissionSelectionActivity.r;
                ArrayList arrayList3 = (ArrayList) this.b;
                if (z3) {
                    arrayList3.add(nVarB0);
                }
                if (isEnabled.booleanValue()) {
                    arrayList3.add(nVarB02);
                }
                arrayList3.add(nVarB03);
                RecyclerView editSetLanguageList = ((C4602f) editSetPermissionSelectionActivity.K()).c;
                Intrinsics.checkNotNullExpressionValue(editSetLanguageList, "editSetLanguageList");
                editSetLanguageList.setAdapter(new p(arrayList3, new C0960p(2, editSetPermissionSelectionActivity, EditSetPermissionSelectionActivity.class, "itemClickCallback", "itemClickCallback(Lcom/quizlet/quizletandroid/util/PermissionMatrix$PermissionAccess;Z)V", 0, 24), editSetPermissionSelectionActivity.s));
                return;
            case 14:
                androidx.core.util.c pair2 = (androidx.core.util.c) obj;
                Intrinsics.checkNotNullParameter(pair2, "pair");
                Object obj4 = pair2.a;
                boolean zBooleanValue = obj4 == null ? false : ((Boolean) obj4).booleanValue();
                Object obj5 = pair2.b;
                boolean zBooleanValue2 = obj5 != null ? ((Boolean) obj5).booleanValue() : false;
                EditSetFragment editSetFragment = (EditSetFragment) this.b;
                com.quizlet.infra.legacysyncengine.managers.d dVar3 = editSetFragment.k;
                if (dVar3 == null) {
                    Intrinsics.m("loggedInUserManager");
                    throw null;
                }
                DBUser dBUser = dVar3.r;
                if (!zBooleanValue) {
                    if (!zBooleanValue2 || dBUser == null) {
                        return;
                    }
                    EditSetFragment.T(editSetFragment, com.quizlet.features.infra.models.upgrade.a.h);
                    return;
                }
                editSetFragment.Y().f = (DBTerm) this.c;
                com.quizlet.quizletandroid.ui.setpage.b bVar6 = new com.quizlet.quizletandroid.ui.setpage.b();
                AbstractC1136h0 childFragmentManager = editSetFragment.getChildFragmentManager();
                Intrinsics.checkNotNullExpressionValue(childFragmentManager, "getChildFragmentManager(...)");
                AbstractC0151c.d(bVar6, childFragmentManager, "AddImageBottomSheet");
                return;
            case 15:
                DBStudySet studySet = (DBStudySet) obj;
                Intrinsics.checkNotNullParameter(studySet, "studySet");
                EditSetFragment editSetFragment2 = (EditSetFragment) this.b;
                com.quizlet.quizletandroid.ui.setcreation.adapters.f fVar2 = editSetFragment2.A;
                if (fVar2 != null) {
                    studySet.getId();
                    String title = studySet.getTitle();
                    String description = studySet.getDescription();
                    fVar2.n = title;
                    fVar2.o = description;
                    fVar2.notifyItemChanged(0);
                }
                com.quizlet.quizletandroid.ui.setcreation.adapters.f fVar3 = editSetFragment2.A;
                if (fVar3 != null) {
                    O1 o1 = O1.WORD;
                    com.quizlet.quizletandroid.util.f fVar4 = editSetFragment2.n;
                    if (fVar4 == null) {
                        Intrinsics.m("languageUtil");
                        throw null;
                    }
                    fVar3.n(o1, fVar4.a(studySet.getWordLang()));
                }
                com.quizlet.quizletandroid.ui.setcreation.adapters.f fVar5 = editSetFragment2.A;
                if (fVar5 != null) {
                    O1 o12 = O1.DEFINITION;
                    com.quizlet.quizletandroid.util.f fVar6 = editSetFragment2.n;
                    if (fVar6 == null) {
                        Intrinsics.m("languageUtil");
                        throw null;
                    }
                    fVar5.n(o12, fVar6.a(studySet.getDefLang()));
                }
                WeakReference weakReference = editSetFragment2.x;
                com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.b bVar7 = weakReference != null ? (com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.b) weakReference.get() : null;
                if (bVar7 == null || (aVar = ((com.quizlet.quizletandroid.ui.setcreation.activities.d) bVar7).m) == null) {
                    return;
                }
                long id = studySet.getId();
                Long lValueOf = Long.valueOf(id);
                com.quizlet.quizletandroid.ui.setcreation.managers.i iVar2 = (com.quizlet.quizletandroid.ui.setcreation.managers.i) this.c;
                boolean z4 = iVar2.s;
                boolean z5 = iVar2.l;
                boolean z6 = id < 0;
                if (z5) {
                    aVar.a.c.setEditSetAction("copy");
                } else if (z6 && z4) {
                    aVar.a.c.setEditSetAction("create");
                } else {
                    aVar.a.c.setEditSetAction("edit");
                }
                if (z6) {
                    aVar.a.c.setClientModelId(lValueOf);
                    return;
                } else {
                    aVar.a.c.setServerModelId(lValueOf);
                    return;
                }
            case 16:
                Boolean isEnabled2 = (Boolean) obj;
                Intrinsics.checkNotNullParameter(isEnabled2, "isEnabled");
                boolean zBooleanValue3 = isEnabled2.booleanValue();
                com.quizlet.quizletandroid.ui.setcreation.viewmodels.e eVar = (com.quizlet.quizletandroid.ui.setcreation.viewmodels.e) this.b;
                if (zBooleanValue3) {
                    eVar.h.l((org.wordpress.aztec.toolbar.c) this.c);
                    return;
                }
                eVar.h.l(null);
                Intrinsics.checkNotNullParameter("android_iap_source_rich_text_editor", "source");
                eVar.l.j(new com.quizlet.quizletandroid.ui.setcreation.navigation.b());
                return;
            case 17:
                com.quizlet.offline.managers.j launchBehavior2 = (com.quizlet.offline.managers.j) obj;
                Intrinsics.checkNotNullParameter(launchBehavior2, "launchBehavior");
                com.quizlet.offline.managers.j jVar4 = com.quizlet.offline.managers.j.a;
                DBStudySet dBStudySet2 = (DBStudySet) this.c;
                com.quizlet.quizletandroid.ui.startpage.nav2.Y y2 = (com.quizlet.quizletandroid.ui.startpage.nav2.Y) this.b;
                if (launchBehavior2 == jVar4) {
                    y2.r1.j(new com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.f(dBStudySet2));
                    return;
                }
                com.quizlet.offline.managers.i iVar3 = (com.quizlet.offline.managers.i) y2.n;
                iVar3.getClass();
                Intrinsics.checkNotNullParameter(launchBehavior2, "launchBehavior");
                if (launchBehavior2 == com.quizlet.offline.managers.j.b) {
                    iVar3.a.I("warned_missing_offline_content");
                }
                y2.r1.j(new w(dBStudySet2.getSetId(), launchBehavior2));
                return;
            case 18:
                io.reactivex.rxjava3.disposables.b it11 = (io.reactivex.rxjava3.disposables.b) obj;
                Intrinsics.checkNotNullParameter(it11, "it");
                int i2 = ((C4756b) this.c).k;
                TextView textView = (TextView) this.b;
                Intrinsics.checkNotNullParameter(textView, "<this>");
                Context context = textView.getContext();
                Intrinsics.checkNotNullExpressionValue(context, "getContext(...)");
                textView.setTextColor(com.quizlet.themes.extensions.a.a(context, i2));
                return;
            case 19:
                Long hs = (Long) obj;
                Intrinsics.checkNotNullParameter(hs, "hs");
                boolean z7 = ((Throwable) this.b) instanceof TimeoutException;
                com.quizlet.quizletandroid.ui.studymodes.match.viewmodel.a aVar6 = (com.quizlet.quizletandroid.ui.studymodes.match.viewmodel.a) this.c;
                if (z7) {
                    Object[] args = new Object[0];
                    Intrinsics.checkNotNullParameter(args, "args");
                    d = new D(new com.quizlet.qutils.string.f(R.string.match_leaderboard_error, C4933y.P(args)), false);
                } else {
                    String str10 = aVar6.o.format(hs.longValue() / 10.0d);
                    Intrinsics.checkNotNullExpressionValue(str10, "format(...)");
                    Object[] args2 = {str10};
                    Intrinsics.checkNotNullParameter(args2, "args");
                    d = new D(new com.quizlet.qutils.string.f(R.string.match_leaderboard_offline, C4933y.P(args2)), true);
                }
                aVar6.l.o(d);
                return;
            case 20:
                List scores = (List) obj;
                Intrinsics.checkNotNullParameter(scores, "highScores");
                com.quizlet.quizletandroid.ui.studymodes.match.viewmodel.a aVar7 = (com.quizlet.quizletandroid.ui.studymodes.match.viewmodel.a) this.b;
                io.reactivex.rxjava3.internal.observers.e eVarI = io.reactivex.rxjava3.core.p.p(aVar7.d.u(), aVar7.q, new com.quizlet.data.interactor.school.b(28, (com.quizlet.features.match.highscore.a) this.c, aVar7)).i(io.reactivex.rxjava3.internal.functions.d.d, io.reactivex.rxjava3.internal.functions.d.e);
                Intrinsics.checkNotNullExpressionValue(eVarI, "subscribe(...)");
                Intrinsics.checkNotNullParameter(eVarI, "<this>");
                aVar7.A(eVarI);
                s sVar = aVar7.i;
                sVar.getClass();
                Intrinsics.checkNotNullParameter(scores, "highScores");
                long personId = ((UserInfoCache) sVar.d).getPersonId();
                Intrinsics.checkNotNullParameter(scores, "scores");
                Iterator it12 = scores.iterator();
                int i3 = 0;
                while (true) {
                    if (!it12.hasNext()) {
                        i3 = -1;
                    } else if (personId != ((com.quizlet.features.match.highscore.a) it12.next()).e) {
                        i3++;
                    }
                }
                aVar7.l.o(new E(scores, i3));
                aVar7.g.c.I("match_leaderboard_shown");
                N n = (N) sVar.b;
                if (n.a <= 0 || n.b || ((com.quizlet.features.match.highscore.b) sVar.f).b.getBoolean("PREF_SHOWN_NEW_TOOL_TIP", false)) {
                    return;
                }
                aVar7.m.j(new com.quizlet.features.match.data.Y(new com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.l(0, aVar7, com.quizlet.quizletandroid.ui.studymodes.match.viewmodel.a.class, "tooltipDismissed", "tooltipDismissed()V", 0, 17)));
                return;
            case 21:
                Boolean enabled = (Boolean) obj;
                Intrinsics.checkNotNullParameter(enabled, "enabled");
                com.quizlet.features.infra.basestudy.data.models.dataproviders.a aVar8 = (com.quizlet.features.infra.basestudy.data.models.dataproviders.a) this.c;
                Intrinsics.d(aVar8);
                boolean zBooleanValue4 = enabled.booleanValue();
                com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.G g2 = (com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.G) this.b;
                ArrayList arrayList4 = aVar8.s;
                if (arrayList4 == null) {
                    throw new IllegalArgumentException("Required value was null.");
                }
                List listA = aVar8.a();
                if (listA == null) {
                    throw new IllegalArgumentException("Required value was null.");
                }
                List listB = aVar8.b();
                if (listB == null) {
                    throw new IllegalArgumentException("Required value was null.");
                }
                kotlinx.coroutines.E.A(p0.j(g2), null, null, new z(g2, arrayList4, listA, listB, zBooleanValue4, aVar8, null), 3);
                return;
            case EventType.WINDOW_STATE /* 22 */:
                com.quizlet.features.infra.basestudy.data.models.dataproviders.a it13 = (com.quizlet.features.infra.basestudy.data.models.dataproviders.a) obj;
                Intrinsics.checkNotNullParameter(it13, "it");
                com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.G g3 = (com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.G) this.b;
                com.quizlet.infra.legacysyncengine.features.properties.d dVar4 = g3.m;
                com.quizlet.featuregate.features.flexiblegrading.a aVar9 = g3.k;
                androidx.work.impl.model.c cVar2 = g3.l;
                io.reactivex.rxjava3.internal.observers.e eVarI2 = io.reactivex.rxjava3.core.p.o(aVar9.b(cVar2, dVar4), cVar2.t(), cVar2.s(), new com.quizlet.quizletandroid.k((InterfaceC4176w0) this.c, 11)).i(new b(21, g3, it13), io.reactivex.rxjava3.internal.functions.d.e);
                Intrinsics.checkNotNullExpressionValue(eVarI2, "subscribe(...)");
                Intrinsics.checkNotNullParameter(eVarI2, "<this>");
                g3.A(eVarI2);
                return;
            case EventType.AUDIO /* 23 */:
                com.quizlet.features.infra.basestudy.data.models.dataproviders.a it14 = (com.quizlet.features.infra.basestudy.data.models.dataproviders.a) obj;
                Intrinsics.checkNotNullParameter(it14, "it");
                com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.G g4 = (com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.G) this.b;
                kotlinx.coroutines.E.A(p0.j(g4), null, null, new B(g4, it14, (TestStudyModeConfig) this.c, null), 3);
                return;
            default:
                com.quizlet.features.infra.basestudy.data.models.dataproviders.a it15 = (com.quizlet.features.infra.basestudy.data.models.dataproviders.a) obj;
                Intrinsics.checkNotNullParameter(it15, "it");
                com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.G g5 = (com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.G) this.b;
                g5.getClass();
                kotlinx.coroutines.E.A(p0.j(g5), null, null, new F(g5, (StudiableQuestion) this.c, null), 3);
                return;
        }
    }

    public /* synthetic */ b(Object obj, ArrayList arrayList, int i) {
        this.a = i;
        this.c = obj;
        this.b = arrayList;
    }
}

package com.quizlet.analytics.marketing;

import android.os.Bundle;
import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.camera.camera2.internal.C0138o;
import androidx.collection.C0209g;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.lifecycle.p0;
import androidx.work.impl.model.v;
import com.comscore.streaming.EventType;
import com.google.android.gms.ads.admanager.AdManagerAdRequest;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3124d5;
import com.google.firebase.analytics.FirebaseAnalytics;
import com.quizlet.data.model.StudySetWithCreator;
import com.quizlet.data.model.Z1;
import com.quizlet.data.repository.metering.j;
import com.quizlet.db.data.models.persisted.DBDiagramShape;
import com.quizlet.db.data.models.persisted.DBUser;
import com.quizlet.db.data.models.wrappers.LoggedInUserStatus;
import com.quizlet.features.infra.basestudy.manager.f;
import com.quizlet.features.infra.legacyadapter.databinding.g;
import com.quizlet.features.infra.legacyadapter.viewholder.k;
import com.quizlet.features.match.data.C4345a;
import com.quizlet.features.match.data.C4349e;
import com.quizlet.features.match.data.Q;
import com.quizlet.features.match.settings.MatchSettingsData;
import com.quizlet.features.match.viewmodel.h;
import com.quizlet.infra.legacysyncengine.datasources.n;
import com.quizlet.infra.legacysyncengine.datasources.p;
import com.quizlet.infra.legacysyncengine.net.request.i;
import com.quizlet.login.oldlogin.o;
import com.quizlet.quizletandroid.ui.setpage.addset.LoggedInUserClassSelectionListFragment;
import com.quizlet.quizletandroid.ui.startpage.nav2.C4700i;
import com.quizlet.studiablemodels.DefaultQuestionSectionData;
import com.quizlet.studiablemodels.LocationQuestionSectionData;
import com.quizlet.studiablemodels.MixedOptionMatchingStudiableQuestion;
import com.quizlet.studiablemodels.QuestionSectionData;
import com.quizlet.studiablemodels.StudiableDiagramImage;
import com.quizlet.studiablemodels.StudiableQuestionMetadata;
import com.quizlet.studiablemodels.diagrams.DiagramData;
import io.reactivex.rxjava3.subjects.r;
import java.io.FileInputStream;
import java.time.Instant;
import java.util.ArrayList;
import java.util.GregorianCalendar;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Pair;
import kotlin.collections.B;
import kotlin.collections.C;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.C4956o;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;
import kotlinx.coroutines.E;

/* loaded from: classes2.dex */
public final class e implements io.reactivex.rxjava3.functions.d {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public /* synthetic */ e(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    /* JADX WARN: Type inference failed for: r14v105, types: [kotlin.jvm.functions.Function0, kotlin.jvm.internal.o] */
    @Override // io.reactivex.rxjava3.functions.d
    public final void accept(Object obj) {
        Object c4349e;
        Map map;
        AdManagerAdRequest adManagerAdRequestBuild;
        long j = -1;
        com.quizlet.features.infra.legacyadapter.section.b bVar = null;
        int i = 0;
        switch (this.a) {
            case 0:
                Boolean it2 = (Boolean) obj;
                Intrinsics.checkNotNullParameter(it2, "it");
                ((Function0) this.b).invoke();
                return;
            case 1:
                DBUser p0 = (DBUser) obj;
                Intrinsics.checkNotNullParameter(p0, "p0");
                ((com.quizlet.braze.e) this.b).a(p0);
                return;
            case 2:
                List<Z1> list = (List) obj;
                Intrinsics.checkNotNullParameter(list, "list");
                com.quizlet.local.ormlite.models.studysetwithcreator.a aVar = (com.quizlet.local.ormlite.models.studysetwithcreator.a) ((v) ((com.quizlet.data.repository.studysetwithcreator.d) this.b).a).b;
                ArrayList arrayList = new ArrayList(C.q(list, 10));
                for (Z1 z1 : list) {
                    arrayList.add(new StudySetWithCreator(z1.a, z1.b));
                }
                aVar.a(arrayList).i(io.reactivex.rxjava3.internal.functions.d.d, io.reactivex.rxjava3.internal.functions.d.e);
                return;
            case 3:
                io.reactivex.rxjava3.disposables.b it3 = (io.reactivex.rxjava3.disposables.b) obj;
                Intrinsics.checkNotNullParameter(it3, "it");
                ((com.quizlet.explanations.textbook.tableofcontents.viewmodel.b) this.b).h.l(Boolean.TRUE);
                return;
            case 4:
                boolean zBooleanValue = ((Boolean) obj).booleanValue();
                ConstraintLayout listitemSetCardLayout = ((g) ((k) this.b).e()).b;
                Intrinsics.checkNotNullExpressionValue(listitemSetCardLayout, "listitemSetCardLayout");
                listitemSetCardLayout.setAlpha(zBooleanValue ? 0.5f : 1.0f);
                return;
            case 5:
                io.reactivex.rxjava3.disposables.b it4 = (io.reactivex.rxjava3.disposables.b) obj;
                Intrinsics.checkNotNullParameter(it4, "it");
                ((com.quizlet.features.infra.studysetting.datasource.a) this.b).d();
                return;
            case 6:
                com.quizlet.features.infra.basestudy.data.models.dataproviders.a provider = (com.quizlet.features.infra.basestudy.data.models.dataproviders.a) obj;
                Intrinsics.checkNotNullParameter(provider, "provider");
                j jVar = (j) this.b;
                com.quizlet.data.repository.folderset.c cVar = (com.quizlet.data.repository.folderset.c) jVar.b;
                com.quizlet.features.infra.studysetting.managers.a manager = ((f) jVar.a).g();
                cVar.getClass();
                Intrinsics.checkNotNullParameter(manager, "manager");
                cVar.d = manager;
                ((r) jVar.d).onSuccess(provider);
                return;
            case 7:
                MixedOptionMatchingStudiableQuestion matchGame = (MixedOptionMatchingStudiableQuestion) obj;
                Intrinsics.checkNotNullParameter(matchGame, "matchGame");
                C0209g c0209g = new C0209g(0);
                com.quizlet.features.match.studyengine.b bVar2 = (com.quizlet.features.match.studyengine.b) this.b;
                bVar2.c = c0209g;
                bVar2.d = matchGame.b.size();
                return;
            case 8:
                MixedOptionMatchingStudiableQuestion p02 = (MixedOptionMatchingStudiableQuestion) obj;
                Intrinsics.checkNotNullParameter(p02, "p0");
                com.quizlet.features.match.studyengine.e eVar = (com.quizlet.features.match.studyengine.e) this.b;
                eVar.f = -1L;
                eVar.g = -1L;
                eVar.h = 0L;
                ArrayList arrayList2 = eVar.b;
                arrayList2.clear();
                eVar.d = p02;
                Iterator it5 = p02.b.iterator();
                while (it5.hasNext()) {
                    Object next = it5.next();
                    int i2 = i + 1;
                    if (i < 0) {
                        B.p();
                        throw null;
                    }
                    QuestionSectionData questionSectionData = (QuestionSectionData) next;
                    Intrinsics.checkNotNullParameter(questionSectionData, "<this>");
                    if (questionSectionData instanceof DefaultQuestionSectionData) {
                        DefaultQuestionSectionData defaultQuestionSectionData = (DefaultQuestionSectionData) questionSectionData;
                        c4349e = new C4345a(i, defaultQuestionSectionData.a, defaultQuestionSectionData.b, defaultQuestionSectionData.c);
                    } else {
                        if (!(questionSectionData instanceof LocationQuestionSectionData)) {
                            throw new NoWhenBranchMatchedException();
                        }
                        LocationQuestionSectionData locationQuestionSectionData = (LocationQuestionSectionData) questionSectionData;
                        c4349e = new C4349e(locationQuestionSectionData.a, locationQuestionSectionData.b);
                    }
                    arrayList2.add(c4349e);
                    i = i2;
                }
                StudiableQuestionMetadata studiableQuestionMetadata = p02.c;
                if (studiableQuestionMetadata.b()) {
                    StudiableDiagramImage studiableDiagramImage = studiableQuestionMetadata.e;
                    if (studiableDiagramImage == null) {
                        throw new IllegalArgumentException("Non-null diagram image required for Diagram match game");
                    }
                    ArrayList arrayList3 = new ArrayList();
                    Iterator it6 = arrayList2.iterator();
                    while (it6.hasNext()) {
                        Object next2 = it6.next();
                        if (next2 instanceof C4349e) {
                            arrayList3.add(next2);
                        }
                    }
                    ArrayList arrayList4 = new ArrayList(C.q(arrayList3, 10));
                    Iterator it7 = arrayList3.iterator();
                    while (it7.hasNext()) {
                        C4349e c4349e2 = (C4349e) it7.next();
                        Intrinsics.checkNotNullParameter(c4349e2, "<this>");
                        DBDiagramShape dBDiagramShape = new DBDiagramShape();
                        dBDiagramShape.setTermId(c4349e2.b);
                        dBDiagramShape.setShape(c4349e2.c.a);
                        arrayList4.add(dBDiagramShape);
                    }
                    DiagramData.Builder builder = new DiagramData.Builder();
                    builder.c(AbstractC3124d5.c(studiableDiagramImage));
                    builder.d(studiableQuestionMetadata.b);
                    builder.b(arrayList4);
                    eVar.c = builder.a();
                }
                eVar.e = true;
                return;
            case 9:
                Q q = (Q) obj;
                Intrinsics.checkNotNullParameter(q, "<destruct>");
                MatchSettingsData matchSettingsData = q.a;
                h hVar = (h) this.b;
                hVar.getClass();
                E.A(p0.j(hVar), null, null, new com.quizlet.features.match.viewmodel.g(q.b, hVar, matchSettingsData, null), 3);
                return;
            case 10:
                io.reactivex.rxjava3.disposables.b it8 = (io.reactivex.rxjava3.disposables.b) obj;
                Intrinsics.checkNotNullParameter(it8, "it");
                ((io.reactivex.rxjava3.subjects.d) ((C0138o) this.b).h).b(com.quizlet.features.setpage.state.b.a);
                return;
            case 11:
                io.reactivex.rxjava3.disposables.b subscription = (io.reactivex.rxjava3.disposables.b) obj;
                Intrinsics.checkNotNullParameter(subscription, "subscription");
                ((com.quizlet.baseui.base.b) this.b).x(subscription);
                return;
            case 12:
                List it9 = (List) obj;
                Intrinsics.checkNotNullParameter(it9, "it");
                n nVar = (n) this.b;
                nVar.h = it9;
                nVar.c();
                return;
            case 13:
                com.quizlet.infra.legacysyncengine.net.request.c it10 = (com.quizlet.infra.legacysyncengine.net.request.c) obj;
                Intrinsics.checkNotNullParameter(it10, "it");
                ((p) this.b).e.b(it10);
                return;
            case 14:
                com.quizlet.infra.legacysyncengine.net.request.c it11 = (com.quizlet.infra.legacysyncengine.net.request.c) obj;
                Intrinsics.checkNotNullParameter(it11, "it");
                ((p) this.b).e.b(it11);
                return;
            case 15:
                com.quizlet.infra.legacysyncengine.tasks.parse.h hVar2 = (com.quizlet.infra.legacysyncengine.tasks.parse.h) obj;
                i iVar = hVar2.c;
                Map map2 = iVar.b;
                if ((map2 == null || map2.size() <= 0) && (((map = iVar.c) == null || map.size() <= 0) && iVar.a == null)) {
                    return;
                }
                ((com.squareup.otto.c) ((com.quizlet.infra.legacysyncengine.net.request.b) this.b).e).c(new com.quizlet.infra.legacysyncengine.events.a(hVar2.c));
                return;
            case 16:
                List selectedTerms = (List) obj;
                Intrinsics.checkNotNullParameter(selectedTerms, "selectedTerms");
                ((io.reactivex.rxjava3.subjects.d) ((com.quizlet.remote.model.notes.e) this.b).f).b(selectedTerms);
                return;
            case 17:
                io.reactivex.rxjava3.disposables.b it12 = (io.reactivex.rxjava3.disposables.b) obj;
                Intrinsics.checkNotNullParameter(it12, "it");
                ((o) this.b).s.j(Boolean.TRUE);
                return;
            case 18:
                Intrinsics.checkNotNullParameter((Pair) obj, "<destruct>");
                timber.log.c.a.g(AbstractC0147y.c(((ArrayList) this.b).size(), "Starting pre-loading from Latest Activity Feed of ", " sets"), new Object[0]);
                return;
            case 19:
                io.reactivex.rxjava3.disposables.b it13 = (io.reactivex.rxjava3.disposables.b) obj;
                Intrinsics.checkNotNullParameter(it13, "it");
                ((C4700i) this.b).accept(it13);
                return;
            case 20:
                Throwable it14 = (Throwable) obj;
                Intrinsics.checkNotNullParameter(it14, "it");
                timber.log.c.a.g("MediaPlayer error occurred: " + it14, new Object[0]);
                ((com.quizlet.quizletandroid.audio.players.h) this.b).b();
                return;
            case 21:
                LoggedInUserStatus userStatus = (LoggedInUserStatus) obj;
                Intrinsics.checkNotNullParameter(userStatus, "userStatus");
                DBUser currentUser = userStatus.getCurrentUser();
                if (currentUser != null) {
                    Bundle bundle = new Bundle();
                    com.quizlet.data.repository.user.a aVar2 = (com.quizlet.data.repository.user.a) this.b;
                    bundle.putString("clientId", ((com.google.android.gms.analytics.c) aVar2.c).a());
                    bundle.putString("isLoggedIn", String.valueOf(userStatus.isLoggedIn()));
                    bundle.putString("locale", currentUser.getMobileLocale());
                    bundle.putString("selfIdentifiedUserType", String.valueOf(currentUser.getSelfIdentifiedUserType()));
                    if (userStatus.getPersonId() == 0) {
                        bundle.putString("userId", null);
                    } else {
                        bundle.putString("userId", String.valueOf(userStatus.getPersonId()));
                    }
                    int birthYear = currentUser.getBirthYear();
                    int birthMonth = currentUser.getBirthMonth();
                    int birthDay = currentUser.getBirthDay();
                    GregorianCalendar dateFrom = new GregorianCalendar();
                    Intrinsics.checkNotNullParameter(dateFrom, "dateFrom");
                    long days = TimeUnit.MILLISECONDS.toDays(dateFrom.getTimeInMillis() - new GregorianCalendar(birthYear, birthMonth, birthDay).getTimeInMillis());
                    bundle.putString("userRange", days >= 12410 ? "34+" : days >= 9125 ? "25-34" : days >= 6570 ? "18-24" : days >= 4745 ? "13-17" : "u13");
                    timber.log.c.a.g("Logging app init event w/ bundle " + bundle, new Object[0]);
                    ((FirebaseAnalytics) aVar2.d).a(bundle, "appInit");
                    return;
                }
                return;
            case EventType.WINDOW_STATE /* 22 */:
                io.reactivex.rxjava3.disposables.b it15 = (io.reactivex.rxjava3.disposables.b) obj;
                Intrinsics.checkNotNullParameter(it15, "it");
                com.quizlet.quizletandroid.managers.audio.h hVar3 = (com.quizlet.quizletandroid.managers.audio.h) this.b;
                hVar3.b(false);
                hVar3.c = it15;
                return;
            case EventType.AUDIO /* 23 */:
                io.reactivex.rxjava3.disposables.b it16 = (io.reactivex.rxjava3.disposables.b) obj;
                Intrinsics.checkNotNullParameter(it16, "it");
                ((com.quizlet.quizletandroid.ui.base.viewmodel.a) this.b).e.j(Boolean.TRUE);
                return;
            case EventType.VIDEO /* 24 */:
                com.quizlet.quizletandroid.ui.common.ads.nativeads.module.a p03 = (com.quizlet.quizletandroid.ui.common.ads.nativeads.module.a) obj;
                Intrinsics.checkNotNullParameter(p03, "p0");
                com.quizlet.quizletandroid.ui.common.ads.nativeads.module.c cVar2 = (com.quizlet.quizletandroid.ui.common.ads.nativeads.module.c) this.b;
                com.quizlet.quizletandroid.ui.common.ads.nativeads.module.f fVar = cVar2.c;
                String str = p03.b;
                synchronized (fVar) {
                    if (!Intrinsics.b(fVar.d, str)) {
                        fVar.d = str;
                        synchronized (fVar) {
                            Iterator it17 = fVar.k.iterator();
                            while (it17.hasNext()) {
                                ((com.quizlet.quizletandroid.ui.common.ads.nativeads.module.d) it17.next()).c = false;
                            }
                            fVar.e(0);
                        }
                    }
                }
                if (!p03.a || p03.c) {
                    com.quizlet.quizletandroid.ui.common.ads.nativeads.module.f fVar2 = cVar2.c;
                    synchronized (fVar2) {
                        if (fVar2.h != 0) {
                            fVar2.h = 0;
                            fVar2.e(0);
                        }
                    }
                    fVar2.a();
                    return;
                }
                com.quizlet.quizletandroid.ui.common.ads.nativeads.module.f fVar3 = cVar2.c;
                int i3 = cVar2.f;
                synchronized (fVar3) {
                    if (i3 != fVar3.h) {
                        fVar3.h = i3;
                        fVar3.e(0);
                    }
                }
                return;
            case EventType.SUBS /* 25 */:
                kotlin.v vVar = (kotlin.v) obj;
                Intrinsics.checkNotNullParameter(vVar, "<destruct>");
                com.google.android.gms.ads.k kVar = (com.google.android.gms.ads.k) vVar.a;
                Object obj2 = vVar.b;
                Intrinsics.checkNotNullExpressionValue(obj2, "component2(...)");
                Map map3 = (Map) obj2;
                Object obj3 = vVar.c;
                Intrinsics.checkNotNullExpressionValue(obj3, "component3(...)");
                Map map4 = (Map) obj3;
                com.quizlet.quizletandroid.ui.common.ads.nativeads.module.f fVar4 = (com.quizlet.quizletandroid.ui.common.ads.nativeads.module.f) this.b;
                synchronized (fVar4) {
                    try {
                        AdManagerAdRequest.Builder builder2 = new AdManagerAdRequest.Builder();
                        for (Map.Entry entry : map3.entrySet()) {
                            builder2.addCustomTargeting((String) entry.getKey(), (List<String>) entry.getValue());
                        }
                        for (Map.Entry entry2 : map4.entrySet()) {
                            builder2.addCustomTargeting((String) entry2.getKey(), (String) entry2.getValue());
                        }
                        String str2 = fVar4.d;
                        if (str2 != null && !StringsKt.O(str2)) {
                            builder2.setContentUrl(coil3.network.g.b(str2));
                        }
                        adManagerAdRequestBuild = builder2.build();
                        Intrinsics.checkNotNullExpressionValue(adManagerAdRequestBuild, "build(...)");
                    } catch (Throwable th) {
                        throw th;
                    }
                }
                kVar.loadAd(adManagerAdRequestBuild);
                return;
            case EventType.CDN /* 26 */:
                FileInputStream fileInputStream = (FileInputStream) obj;
                Intrinsics.checkNotNullParameter(fileInputStream, "fileInputStream");
                ((com.quizlet.quizletandroid.ui.common.images.loading.glide.f) this.b).c = fileInputStream;
                return;
            case 27:
                Pair pair = (Pair) obj;
                Intrinsics.checkNotNullParameter(pair, "<destruct>");
                List<com.quizlet.quizletandroid.ui.group.classcontent.models.a> list2 = (List) pair.a;
                boolean zBooleanValue2 = ((Boolean) pair.b).booleanValue();
                com.quizlet.quizletandroid.ui.group.classcontent.viewmodel.a aVar3 = (com.quizlet.quizletandroid.ui.group.classcontent.viewmodel.a) this.b;
                boolean zIsEmpty = list2.isEmpty();
                com.quizlet.viewmodel.livedata.b bVar3 = aVar3.l;
                if (zIsEmpty) {
                    if (zBooleanValue2) {
                        bVar3.o(com.quizlet.quizletandroid.ui.group.classcontent.viewmodel.f.a);
                        return;
                    } else {
                        bVar3.o(com.quizlet.quizletandroid.ui.group.classcontent.viewmodel.g.a);
                        return;
                    }
                }
                ArrayList arrayList5 = new ArrayList();
                aVar3.k.getClass();
                long jCurrentTimeMillis = System.currentTimeMillis();
                for (com.quizlet.quizletandroid.ui.group.classcontent.models.a aVar4 : list2) {
                    long epochMilli = Instant.ofEpochSecond(aVar4.a()).toEpochMilli();
                    com.quizlet.quizletandroid.util.o oVar = aVar3.e;
                    long jA = oVar.a(jCurrentTimeMillis, epochMilli);
                    if (bVar == null || j != jA) {
                        com.quizlet.features.infra.legacyadapter.section.b bVar4 = new com.quizlet.features.infra.legacyadapter.section.b(oVar, jA);
                        arrayList5.add(new com.quizlet.quizletandroid.ui.group.classcontent.models.e(bVar4));
                        bVar = bVar4;
                        j = jA;
                    }
                    arrayList5.add(aVar4);
                }
                bVar3.o(new com.quizlet.quizletandroid.ui.group.classcontent.viewmodel.e(arrayList5));
                return;
            case 28:
                com.jakewharton.rxbinding4.widget.a it18 = (com.jakewharton.rxbinding4.widget.a) obj;
                Intrinsics.checkNotNullParameter(it18, "it");
                ((C4956o) this.b).invoke();
                return;
            default:
                Intrinsics.checkNotNullParameter((List) obj, "p0");
                String str3 = LoggedInUserClassSelectionListFragment.F;
                ((LoggedInUserClassSelectionListFragment) this.b).t.notifyDataSetChanged();
                return;
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    public e(Function0 function0) {
        this.a = 28;
        this.b = (C4956o) function0;
    }
}

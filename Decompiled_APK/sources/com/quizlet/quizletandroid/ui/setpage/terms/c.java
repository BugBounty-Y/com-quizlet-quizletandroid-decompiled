package com.quizlet.quizletandroid.ui.setpage.terms;

import android.content.Context;
import androidx.compose.material3.C0676l1;
import androidx.lifecycle.C;
import androidx.lifecycle.X;
import androidx.lifecycle.p0;
import com.google.android.gms.ads.admanager.AdManagerAdView;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3170i6;
import com.quizlet.eventlogger.features.home.HomeEventLog;
import com.quizlet.features.match.data.C4346b;
import com.quizlet.features.match.data.C4347c;
import com.quizlet.features.match.data.C4349e;
import com.quizlet.features.match.data.C4358n;
import com.quizlet.features.match.data.C4359o;
import com.quizlet.features.match.data.P;
import com.quizlet.features.match.data.S;
import com.quizlet.features.setpage.viewmodel.C4437k;
import com.quizlet.generated.enums.U;
import com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.C4746o;
import com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.L;
import com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.C4756b;
import com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.i;
import com.quizlet.quizletandroid.ui.usersettings.fragments.CropImageFragment;
import com.quizlet.studiablemodels.RoundResultItem;
import io.reactivex.rxjava3.core.p;
import io.reactivex.rxjava3.internal.operators.maybe.j;
import io.reactivex.rxjava3.internal.operators.maybe.w;
import io.reactivex.rxjava3.subjects.r;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.NoSuchElementException;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.collections.B;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.E;

/* loaded from: classes3.dex */
public final class c implements io.reactivex.rxjava3.functions.d {
    public final /* synthetic */ int a;
    public final Object b;

    public /* synthetic */ c(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    /* JADX WARN: Type inference failed for: r4v1, types: [io.reactivex.rxjava3.disposables.b, java.util.concurrent.atomic.AtomicReference] */
    @Override // io.reactivex.rxjava3.functions.d
    public final void accept(Object obj) {
        switch (this.a) {
            case 0:
                com.quizlet.infra.legacysyncengine.features.properties.d studySetProperties = (com.quizlet.infra.legacysyncengine.features.properties.d) obj;
                Intrinsics.checkNotNullParameter(studySetProperties, "studySetProperties");
                TermListFragment termListFragment = (TermListFragment) this.b;
                com.google.mlkit.vision.documentscanner.internal.c cVar = termListFragment.x;
                if (cVar == null) {
                    Intrinsics.m("setPageAdFeature");
                    throw null;
                }
                androidx.work.impl.model.c cVar2 = termListFragment.z;
                if (cVar2 == null) {
                    Intrinsics.m("userProperties");
                    throw null;
                }
                io.reactivex.rxjava3.internal.operators.single.g shouldShowAds = cVar.o(cVar2, studySetProperties);
                com.quizlet.quizletandroid.ui.common.ads.nativeads.module.c listener = termListFragment.y;
                String str = "adModule";
                if (listener == null) {
                    Intrinsics.m("adModule");
                    throw null;
                }
                Context context = termListFragment.requireContext();
                Intrinsics.checkNotNullExpressionValue(context, "requireContext(...)");
                List adUnitResources = termListFragment.A;
                if (adUnitResources == null) {
                    Intrinsics.m("nativeAdIdList");
                    throw null;
                }
                io.reactivex.rxjava3.subjects.h hVar = termListFragment.b0().x1;
                C4437k c4437k = C4437k.d;
                hVar.getClass();
                w contentUrl = new j(hVar, c4437k, 1).h();
                Intrinsics.checkNotNullExpressionValue(contentUrl, "toSingle(...)");
                Intrinsics.checkNotNullParameter(context, "context");
                Intrinsics.checkNotNullParameter(shouldShowAds, "shouldShowAds");
                Intrinsics.checkNotNullParameter(adUnitResources, "adUnitResources");
                Intrinsics.checkNotNullParameter(contentUrl, "contentUrlObservable");
                C0676l1 c0676l1 = listener.b;
                c0676l1.a = 3;
                c0676l1.b = 12;
                listener.f = adUnitResources.size();
                com.quizlet.quizletandroid.ui.common.ads.nativeads.module.f fVar = listener.c;
                Intrinsics.checkNotNullParameter(context, "context");
                Intrinsics.checkNotNullParameter(adUnitResources, "adUnitResources");
                Intrinsics.checkNotNullParameter(listener, "listener");
                fVar.c = listener;
                fVar.k = new ArrayList(adUnitResources.size());
                Iterator it2 = adUnitResources.iterator();
                int i = 0;
                while (it2.hasNext()) {
                    Object next = it2.next();
                    int i2 = i + 1;
                    if (i < 0) {
                        B.p();
                        throw null;
                    }
                    int iIntValue = ((Number) next).intValue();
                    com.quizlet.ads.c.b.getClass();
                    com.quizlet.ads.c cVarR = com.google.mlkit.common.sdkinternal.model.a.r(iIntValue);
                    List sizes = cVarR.a(AbstractC3170i6.i(context));
                    com.quizlet.quizletandroid.ui.common.ads.nativeads.module.e listener2 = new com.quizlet.quizletandroid.ui.common.ads.nativeads.module.e(fVar, i);
                    Intrinsics.checkNotNullParameter(context, "context");
                    String str2 = str;
                    Intrinsics.checkNotNullParameter(sizes, "sizes");
                    Intrinsics.checkNotNullParameter(listener2, "listener");
                    AdManagerAdView adManagerAdView = new AdManagerAdView(context);
                    Iterator it3 = it2;
                    adManagerAdView.setAdUnitId(adManagerAdView.getResources().getString(cVarR.a));
                    com.google.android.gms.ads.h[] hVarArr = (com.google.android.gms.ads.h[]) sizes.toArray(new com.google.android.gms.ads.h[0]);
                    adManagerAdView.setAdSizes((com.google.android.gms.ads.h[]) Arrays.copyOf(hVarArr, hVarArr.length));
                    adManagerAdView.setAdListener(listener2);
                    fVar.k.add(i, new com.quizlet.quizletandroid.ui.common.ads.nativeads.module.d(cVarR, adManagerAdView));
                    i = i2;
                    str = str2;
                    context = context;
                    it2 = it3;
                }
                String str3 = str;
                fVar.d = null;
                androidx.work.impl.model.c userProperties = listener.a;
                Intrinsics.checkNotNullParameter(shouldShowAds, "shouldShowAds");
                Intrinsics.checkNotNullParameter(contentUrl, "contentUrl");
                Intrinsics.checkNotNullParameter(userProperties, "userProperties");
                listener.d.dispose();
                p pVarO = p.o(shouldShowAds, contentUrl, userProperties.o(new com.quizlet.quizletandroid.config.features.properties.d(1), Boolean.FALSE), com.quizlet.quizletandroid.ui.common.ads.nativeads.module.b.b);
                Intrinsics.checkNotNullExpressionValue(pVarO, "zip(...)");
                listener.d = pVarO.i(new com.quizlet.analytics.marketing.e(listener, 24), new com.quizlet.billing.manager.d(timber.log.c.a, 8));
                C lifecycle = termListFragment.getLifecycle();
                com.quizlet.quizletandroid.ui.common.ads.nativeads.module.c cVar3 = termListFragment.y;
                if (cVar3 != null) {
                    lifecycle.a(cVar3);
                    return;
                } else {
                    Intrinsics.m(str3);
                    throw null;
                }
            case 1:
                Boolean isEnabled = (Boolean) obj;
                Intrinsics.checkNotNullParameter(isEnabled, "isEnabled");
                if (isEnabled.booleanValue()) {
                    L l = (L) this.b;
                    com.quizlet.quizletandroid.ui.startpage.nav2.logging.c cVar4 = l.h;
                    cVar4.getClass();
                    cVar4.a.l(HomeEventLog.Companion.b(HomeEventLog.b, "LoggedInHomepage", "bottom_nav", "clicked_home", U.CLICK.a(), null, 496));
                    l.p.h(C4746o.a);
                    l.r.j(Unit.a);
                    return;
                }
                return;
            case 2:
                io.reactivex.rxjava3.disposables.b it4 = (io.reactivex.rxjava3.disposables.b) obj;
                Intrinsics.checkNotNullParameter(it4, "it");
                ((C4756b) this.b).h.setSelected(true);
                return;
            case 3:
                List list = (List) obj;
                ArrayList arrayListM = assistantMode.refactored.a.m("list", list);
                Iterator it5 = list.iterator();
                while (true) {
                    boolean zHasNext = it5.hasNext();
                    i iVar = (i) this.b;
                    if (!zHasNext) {
                        iVar.getClass();
                        E.A(p0.j(iVar), null, null, new com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.h(iVar, arrayListM, null), 3);
                        return;
                    }
                    Object next2 = it5.next();
                    com.quizlet.learn.checkpoint.data.d dVar = (com.quizlet.learn.checkpoint.data.d) next2;
                    List listC = iVar.k.c();
                    ArrayList arrayList = new ArrayList(kotlin.collections.C.q(listC, 10));
                    Iterator it6 = listC.iterator();
                    while (it6.hasNext()) {
                        arrayList.add(Long.valueOf(((RoundResultItem) it6.next()).a));
                    }
                    if (arrayList.contains(Long.valueOf(dVar.a.a))) {
                        arrayListM.add(next2);
                    }
                }
            case 4:
                com.quizlet.diagrams.f event = (com.quizlet.diagrams.f) obj;
                Intrinsics.checkNotNullParameter(event, "p0");
                com.quizlet.features.match.viewmodel.d dVar2 = (com.quizlet.features.match.viewmodel.d) this.b;
                dVar2.getClass();
                Intrinsics.checkNotNullParameter(event, "event");
                Iterator it7 = ((C4346b) dVar2.C()).b.iterator();
                while (it7.hasNext()) {
                    C4349e c4349e = (C4349e) it7.next();
                    if (c4349e.b == event.a) {
                        if (c4349e.a instanceof C4358n) {
                            c4349e.b(!c4349e.a());
                            Long l2 = dVar2.l;
                            long j = c4349e.b;
                            int iOrdinal = com.quizlet.features.match.viewmodel.c.E(c4349e, l2, Long.valueOf(j)).ordinal();
                            if (iOrdinal == 0) {
                                dVar2.l = Long.valueOf(j);
                            } else if (iOrdinal == 1) {
                                dVar2.l = null;
                            } else {
                                if (iOrdinal == 2) {
                                    Long l3 = dVar2.l;
                                    if (l3 == null) {
                                        throw new IllegalArgumentException("Required value was null.");
                                    }
                                    long jLongValue = l3.longValue();
                                    Iterator it8 = ((C4346b) dVar2.C()).b.iterator();
                                    while (it8.hasNext()) {
                                        C4349e c4349e2 = (C4349e) it8.next();
                                        if (c4349e2.b == jLongValue) {
                                            c4349e2.b(false);
                                            dVar2.l = Long.valueOf(j);
                                        }
                                    }
                                    throw new NoSuchElementException("Collection contains no element matching the predicate.");
                                }
                                if (iOrdinal != 3) {
                                    throw new NoWhenBranchMatchedException();
                                }
                            }
                            Long l4 = dVar2.l;
                            Integer num = dVar2.k;
                            if (l4 != null && num != null) {
                                dVar2.B(new C4347c(num.intValue(), l4.longValue()));
                            }
                            dVar2.I();
                            return;
                        }
                        return;
                    }
                }
                throw new NoSuchElementException("Collection contains no element matching the predicate.");
            case 5:
                Throwable p0 = (Throwable) obj;
                Intrinsics.checkNotNullParameter(p0, "p0");
                com.quizlet.quizletandroid.ui.studymodes.match.viewmodel.a aVar = (com.quizlet.quizletandroid.ui.studymodes.match.viewmodel.a) this.b;
                io.reactivex.rxjava3.internal.observers.e eVarI = ((r) aVar.i.i).i(new com.quizlet.billing.manager.b(19, p0, aVar), io.reactivex.rxjava3.internal.functions.d.e);
                Intrinsics.checkNotNullExpressionValue(eVarI, "subscribe(...)");
                Intrinsics.checkNotNullParameter(eVarI, "<this>");
                aVar.A(eVarI);
                return;
            case 6:
                C4359o p02 = (C4359o) obj;
                Intrinsics.checkNotNullParameter(p02, "p0");
                ((com.quizlet.viewmodel.livedata.b) this.b).o(p02);
                return;
            case 7:
                Boolean isUnderAge = (Boolean) obj;
                Intrinsics.checkNotNullParameter(isUnderAge, "isUnderAge");
                if (isUnderAge.booleanValue()) {
                    ((com.quizlet.quizletandroid.ui.studymodes.match.viewmodel.g) this.b).s.j(P.a);
                    return;
                }
                return;
            case 8:
                S p03 = (S) obj;
                Intrinsics.checkNotNullParameter(p03, "p0");
                ((X) this.b).j(p03);
                return;
            case 9:
                io.reactivex.rxjava3.disposables.b it9 = (io.reactivex.rxjava3.disposables.b) obj;
                Intrinsics.checkNotNullParameter(it9, "it");
                ((CropImageFragment) this.b).Q(true);
                return;
            case 10:
                ((io.reactivex.rxjava3.functions.a) this.b).run();
                return;
            default:
                Intrinsics.checkNotNullExpressionValue(((Function1) this.b).invoke(obj), "invoke(...)");
                return;
        }
    }
}

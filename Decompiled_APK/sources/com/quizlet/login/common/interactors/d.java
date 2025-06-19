package com.quizlet.login.common.interactors;

import android.content.Context;
import android.content.SharedPreferences;
import android.view.View;
import androidx.compose.animation.d0;
import androidx.fragment.app.I;
import com.braze.Braze;
import com.google.android.gms.ads.admanager.AdManagerAdRequest;
import com.google.android.gms.internal.ads.Zh;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3135e7;
import com.quizlet.db.data.models.base.DBModel;
import com.quizlet.db.data.models.persisted.DBStudySet;
import com.quizlet.db.data.models.persisted.base.Models;
import com.quizlet.eventlogger.EventLogger;
import com.quizlet.eventlogger.EventLoggerExt;
import com.quizlet.generated.enums.w1;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.ui.common.ads.G;
import com.quizlet.quizletandroid.ui.common.ads.InterfaceC4638e;
import com.quizlet.quizletandroid.ui.login.BaseSignupFragment;
import com.quizlet.quizletandroid.ui.profile.UserSetListFragment;
import com.quizlet.quizletandroid.ui.startpage.nav2.model.E;
import com.quizlet.quizletandroid.ui.startpage.nav2.model.S;
import com.quizlet.remote.service.InterfaceC4776c;
import com.quizlet.remote.service.InterfaceC4778e;
import com.quizlet.uicommon.ui.common.views.StatefulTintImageView;
import com.quizlet.uicommon.ui.common.widgets.QFormField;
import com.skydoves.balloon.Balloon;
import io.ktor.http.AbstractC4879a;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.function.BiConsumer;
import kotlin.collections.A;
import kotlin.collections.B;
import kotlin.collections.C;
import kotlin.collections.CollectionsKt;
import kotlin.collections.K;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;
import okhttp3.J;
import org.prebid.mobile.BannerAdUnit;
import retrofit2.InterfaceC5186k;

/* loaded from: classes3.dex */
public final class d implements io.reactivex.rxjava3.functions.h, InterfaceC4638e, com.quizlet.uicommon.ui.common.widgets.e, com.quizlet.features.infra.legacyadapter.d, io.ktor.http.t, InterfaceC5186k {
    public final /* synthetic */ int a;
    public final Object b;

    public /* synthetic */ d(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // io.ktor.util.m
    public Set a() {
        return ((io.ktor.util.n) AbstractC3135e7.b((io.ktor.http.u) this.b)).a();
    }

    @Override // io.reactivex.rxjava3.functions.h
    public Object apply(Object obj) {
        Object next;
        switch (this.a) {
            case 1:
                com.quizlet.quizletandroid.data.management.a info = (com.quizlet.quizletandroid.data.management.a) obj;
                Intrinsics.checkNotNullParameter(info, "p0");
                com.google.android.datatransport.cct.internal.s sVar = (com.google.android.datatransport.cct.internal.s) this.b;
                sVar.getClass();
                Intrinsics.checkNotNullParameter(info, "info");
                io.reactivex.rxjava3.internal.operators.maybe.h hVar = new io.reactivex.rxjava3.internal.operators.maybe.h(3, sVar.f(info), new com.quizlet.data.repository.qclass.c(25, sVar, info));
                Intrinsics.checkNotNullExpressionValue(hVar, "flatMapMaybe(...)");
                return hVar;
            case 7:
                DBStudySet it2 = (DBStudySet) obj;
                Intrinsics.checkNotNullParameter(it2, "it");
                ((Zh) this.b).getClass();
                com.jakewharton.rxbinding4.a aVarO = io.reactivex.rxjava3.core.i.o(B.j(Models.IMAGE, Models.TERM, Models.STUDY_SET));
                Intrinsics.checkNotNullExpressionValue(aVarO, "fromIterable(...)");
                return aVarO;
            case 9:
                List studySets = (List) obj;
                Intrinsics.checkNotNullParameter(studySets, "studySets");
                if (studySets.isEmpty()) {
                    return K.a;
                }
                Iterator it3 = studySets.iterator();
                while (true) {
                    if (it3.hasNext()) {
                        next = it3.next();
                        DBStudySet dBStudySet = (DBStudySet) next;
                        if (dBStudySet.getHasDiagrams() || dBStudySet.getNumTerms() < 10) {
                        }
                    } else {
                        next = null;
                    }
                }
                ((androidx.work.impl.model.e) this.b).getClass();
                List<DBStudySet> listP0 = CollectionsKt.p0(studySets, 6);
                ArrayList arrayList = new ArrayList(C.q(listP0, 10));
                for (DBStudySet dBStudySet2 : listP0) {
                    arrayList.add(new S(dBStudySet2, Long.valueOf(dBStudySet2.getSetId()), w1.RECENT_FEED, false));
                }
                return A.b(new E(arrayList));
            default:
                Object objApply = ((io.reactivex.rxjava3.functions.h) ((io.reactivex.rxjava3.internal.operators.maybe.w) this.b).c).apply(new Object[]{obj});
                Objects.requireNonNull(objApply, "The zipper returned a null value");
                return objApply;
        }
    }

    @Override // com.quizlet.features.infra.legacyadapter.d
    public /* bridge */ /* synthetic */ boolean b(View view, int i, DBModel dBModel) {
        return false;
    }

    @Override // com.quizlet.quizletandroid.ui.common.ads.InterfaceC4638e
    public void c() {
    }

    @Override // retrofit2.InterfaceC5186k
    public Object convert(Object obj) {
        return Optional.ofNullable(((InterfaceC5186k) this.b).convert((J) obj));
    }

    @Override // com.quizlet.features.infra.legacyadapter.d
    public boolean d(View view, int i, DBModel dBModel) {
        DBStudySet dBStudySet = (DBStudySet) dBModel;
        if (dBStudySet == null) {
            return false;
        }
        UserSetListFragment userSetListFragment = (UserSetListFragment) this.b;
        com.quizlet.features.setpage.utils.setpermissions.a aVar = userSetListFragment.w;
        I activity = userSetListFragment.getActivity();
        Intrinsics.e(activity, "null cannot be cast to non-null type com.quizlet.baseui.base.BaseActivity");
        userSetListFragment.I(((com.quizlet.features.setpage.utils.setpermissions.f) aVar).a(dBStudySet, (com.quizlet.baseui.base.b) activity, new G(this, 12)).e());
        return true;
    }

    @Override // io.ktor.util.m
    public void e(String name, List values) {
        Intrinsics.checkNotNullParameter(name, "name");
        Intrinsics.checkNotNullParameter(values, "values");
        String strE = AbstractC4879a.e(name, false);
        ArrayList arrayList = new ArrayList(C.q(values, 10));
        Iterator it2 = values.iterator();
        while (it2.hasNext()) {
            String str = (String) it2.next();
            Intrinsics.checkNotNullParameter(str, "<this>");
            arrayList.add(AbstractC4879a.e(str, true));
        }
        ((io.ktor.http.u) this.b).e(strE, arrayList);
    }

    @Override // com.quizlet.uicommon.ui.common.widgets.e
    public boolean f(QFormField formField) {
        Intrinsics.checkNotNullParameter(formField, "formField");
        return true;
    }

    @Override // com.quizlet.uicommon.ui.common.widgets.e
    public CharSequence g(Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        return null;
    }

    @Override // io.ktor.util.m
    public List h(String name) {
        Intrinsics.checkNotNullParameter(name, "name");
        List listH = ((io.ktor.http.u) this.b).h(AbstractC4879a.e(name, false));
        if (listH == null) {
            return null;
        }
        ArrayList arrayList = new ArrayList(C.q(listH, 10));
        Iterator it2 = listH.iterator();
        while (it2.hasNext()) {
            arrayList.add(AbstractC4879a.d(0, 0, (String) it2.next(), 11));
        }
        return arrayList;
    }

    @Override // com.quizlet.quizletandroid.ui.common.ads.InterfaceC4638e
    public void i() {
        com.quizlet.quizletandroid.ui.common.ads.prebid.g gVar = (com.quizlet.quizletandroid.ui.common.ads.prebid.g) this.b;
        com.quizlet.quizletandroid.ui.common.ads.prebid.creators.b bVar = gVar.d;
        if (bVar == null) {
            Intrinsics.m("input");
            throw null;
        }
        String str = bVar.e.b;
        AdManagerAdRequest.Builder builder = gVar.c;
        if (str != null && !StringsKt.O(str)) {
            builder.setContentUrl(coil3.network.g.b(str));
        }
        com.quizlet.quizletandroid.ui.common.ads.prebid.creators.b bVar2 = gVar.d;
        if (bVar2 == null) {
            Intrinsics.m("input");
            throw null;
        }
        final com.quizlet.quizletandroid.ui.common.ads.prebid.d dVar = new com.quizlet.quizletandroid.ui.common.ads.prebid.d(2, 8, AdManagerAdRequest.Builder.class, builder, "addCustomTargeting", "addCustomTargeting(Ljava/lang/String;Ljava/lang/String;)Lcom/google/android/gms/ads/AbstractAdRequestBuilder;");
        final int i = 0;
        bVar2.f.forEach(new BiConsumer() { // from class: com.quizlet.quizletandroid.ui.common.ads.prebid.c
            @Override // java.util.function.BiConsumer
            public final void accept(Object obj, Object obj2) {
                switch (i) {
                    case 0:
                        ((d) dVar).invoke(obj, obj2);
                        break;
                    case 1:
                        ((e) dVar).invoke(obj, obj2);
                        break;
                    default:
                        ((f) dVar).invoke(obj, obj2);
                        break;
                }
            }
        });
        com.quizlet.quizletandroid.ui.common.ads.prebid.creators.b bVar3 = gVar.d;
        if (bVar3 == null) {
            Intrinsics.m("input");
            throw null;
        }
        final com.quizlet.quizletandroid.ui.common.ads.prebid.e eVar = new com.quizlet.quizletandroid.ui.common.ads.prebid.e(2, 8, AdManagerAdRequest.Builder.class, builder, "addCustomTargeting", "addCustomTargeting(Ljava/lang/String;Ljava/lang/String;)Lcom/google/android/gms/ads/AbstractAdRequestBuilder;");
        final int i2 = 1;
        bVar3.g.forEach(new BiConsumer() { // from class: com.quizlet.quizletandroid.ui.common.ads.prebid.c
            @Override // java.util.function.BiConsumer
            public final void accept(Object obj, Object obj2) {
                switch (i2) {
                    case 0:
                        ((d) eVar).invoke(obj, obj2);
                        break;
                    case 1:
                        ((e) eVar).invoke(obj, obj2);
                        break;
                    default:
                        ((f) eVar).invoke(obj, obj2);
                        break;
                }
            }
        });
        com.quizlet.quizletandroid.ui.common.ads.prebid.creators.b bVar4 = gVar.d;
        if (bVar4 == null) {
            Intrinsics.m("input");
            throw null;
        }
        Map map = (Map) bVar4.h.b;
        final com.quizlet.quizletandroid.ui.common.ads.prebid.f fVar = new com.quizlet.quizletandroid.ui.common.ads.prebid.f(2, 8, AdManagerAdRequest.Builder.class, builder, "addCustomTargeting", "addCustomTargeting(Ljava/lang/String;Ljava/util/List;)Lcom/google/android/gms/ads/AbstractAdRequestBuilder;");
        final int i3 = 2;
        map.forEach(new BiConsumer() { // from class: com.quizlet.quizletandroid.ui.common.ads.prebid.c
            @Override // java.util.function.BiConsumer
            public final void accept(Object obj, Object obj2) {
                switch (i3) {
                    case 0:
                        ((d) fVar).invoke(obj, obj2);
                        break;
                    case 1:
                        ((e) fVar).invoke(obj, obj2);
                        break;
                    default:
                        ((f) fVar).invoke(obj, obj2);
                        break;
                }
            }
        });
        AdManagerAdRequest adManagerAdRequestBuild = builder.build();
        Intrinsics.checkNotNullExpressionValue(adManagerAdRequestBuild, "build(...)");
        ((BannerAdUnit) gVar.e.getValue()).a(adManagerAdRequestBuild, new com.google.firebase.tracing.a(24, gVar, adManagerAdRequestBuild));
    }

    @Override // com.quizlet.uicommon.ui.common.widgets.e
    public void j(QFormField formField) {
        Intrinsics.checkNotNullParameter(formField, "formField");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object k(java.lang.String r7, kotlin.coroutines.jvm.internal.c r8) throws java.lang.Throwable {
        /*
            r6 = this;
            boolean r0 = r8 instanceof com.quizlet.login.common.interactors.b
            if (r0 == 0) goto L13
            r0 = r8
            com.quizlet.login.common.interactors.b r0 = (com.quizlet.login.common.interactors.b) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.quizlet.login.common.interactors.b r0 = new com.quizlet.login.common.interactors.b
            r0.<init>(r6, r8)
        L18:
            java.lang.Object r8 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            com.quizlet.login.common.interactors.data.h r3 = com.quizlet.login.common.interactors.data.h.a
            r4 = 1
            if (r2 == 0) goto L31
            if (r2 != r4) goto L29
            androidx.glance.appwidget.protobuf.Z.e(r8)     // Catch: java.lang.Exception -> L6d
            goto L57
        L29:
            java.lang.IllegalStateException r7 = new java.lang.IllegalStateException
            java.lang.String r8 = "call to 'resume' before 'invoke' with coroutine"
            r7.<init>(r8)
            throw r7
        L31:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            boolean r8 = kotlin.text.StringsKt.O(r7)
            if (r8 == 0) goto L3d
            com.quizlet.login.common.interactors.data.f r7 = com.quizlet.login.common.interactors.data.f.a
            return r7
        L3d:
            boolean r8 = com.quizlet.qutils.string.c.c(r7)
            if (r8 != 0) goto L44
            goto L69
        L44:
            kotlinx.coroutines.scheduling.e r8 = kotlinx.coroutines.O.a     // Catch: java.lang.Exception -> L6d
            kotlinx.coroutines.scheduling.d r8 = kotlinx.coroutines.scheduling.d.b     // Catch: java.lang.Exception -> L6d
            com.quizlet.login.common.interactors.c r2 = new com.quizlet.login.common.interactors.c     // Catch: java.lang.Exception -> L6d
            r5 = 0
            r2.<init>(r6, r7, r5)     // Catch: java.lang.Exception -> L6d
            r0.l = r4     // Catch: java.lang.Exception -> L6d
            java.lang.Object r8 = kotlinx.coroutines.E.J(r8, r2, r0)     // Catch: java.lang.Exception -> L6d
            if (r8 != r1) goto L57
            return r1
        L57:
            java.lang.String r7 = "withContext(...)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r8, r7)     // Catch: java.lang.Exception -> L6d
            com.quizlet.data.model.B r8 = (com.quizlet.data.model.B) r8     // Catch: java.lang.Exception -> L6d
            boolean r7 = r8.b     // Catch: java.lang.Exception -> L6d
            if (r7 == 0) goto L65
            com.quizlet.login.common.interactors.data.e r7 = com.quizlet.login.common.interactors.data.e.a     // Catch: java.lang.Exception -> L6d
            return r7
        L65:
            boolean r7 = r8.a     // Catch: java.lang.Exception -> L6d
            if (r7 != 0) goto L6a
        L69:
            return r3
        L6a:
            com.quizlet.login.common.interactors.data.i r7 = com.quizlet.login.common.interactors.data.i.a     // Catch: java.lang.Exception -> L6d
            return r7
        L6d:
            com.quizlet.login.common.interactors.data.g r7 = com.quizlet.login.common.interactors.data.g.a
            return r7
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.login.common.interactors.d.k(java.lang.String, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public void l() {
        com.google.android.gms.measurement.internal.J j = (com.google.android.gms.measurement.internal.J) this.b;
        com.onetrust.otpublishers.headless.UI.fragment.q qVar = (com.onetrust.otpublishers.headless.UI.fragment.q) j.e;
        EventLoggerExt.c((EventLogger) qVar.b, new com.quizlet.features.notes.logging.c("explanations_upsell_dismissed", 22));
        SharedPreferences sharedPreferences = ((com.quizlet.features.setpage.upsell.a) j.d).a;
        SharedPreferences.Editor editorEdit = sharedPreferences.edit();
        long j2 = j.b;
        editorEdit.putInt(d0.s(new Object[]{Long.valueOf(j2)}, 1, "explanations_upsell_dismissed_counter_%s", "format(...)"), sharedPreferences.getInt(d0.s(new Object[]{Long.valueOf(j2)}, 1, "explanations_upsell_dismissed_counter_%s", "format(...)"), 0) + 1).apply();
        SharedPreferences.Editor editorEdit2 = sharedPreferences.edit();
        String strS = d0.s(new Object[]{Long.valueOf(j2)}, 1, "explanations_upsell_last_dismissed_ts_%s", "format(...)");
        Instant instantNow = Instant.now();
        Intrinsics.checkNotNullExpressionValue(instantNow, "now(...)");
        editorEdit2.putLong(strS, instantNow.getEpochSecond()).apply();
    }

    @Override // com.quizlet.uicommon.ui.common.widgets.e
    public void m(QFormField formField, StatefulTintImageView view) {
        Intrinsics.checkNotNullParameter(formField, "formField");
        Intrinsics.checkNotNullParameter(view, "view");
        kotlin.u uVar = ((BaseSignupFragment) this.b).o;
        if (((Balloon) uVar.getValue()).isShowing()) {
            ((Balloon) uVar.getValue()).dismiss();
        } else {
            Balloon.showAlignTop$default((Balloon) uVar.getValue(), view, 0, 0, 6, null);
        }
    }

    @Override // com.quizlet.uicommon.ui.common.widgets.e
    public int n() {
        return R.drawable.ic_sys_circle_info;
    }

    @Override // io.ktor.util.m
    public Set names() {
        Set setKeySet = ((Map) ((io.ktor.http.u) this.b).b).keySet();
        ArrayList arrayList = new ArrayList(C.q(setKeySet, 10));
        Iterator it2 = setKeySet.iterator();
        while (it2.hasNext()) {
            arrayList.add(AbstractC4879a.d(0, 0, (String) it2.next(), 15));
        }
        return CollectionsKt.A0(arrayList);
    }

    public d(com.quizlet.db.b upgradeTargetManager) {
        this.a = 11;
        Intrinsics.checkNotNullParameter(upgradeTargetManager, "upgradeTargetManager");
        this.b = upgradeTargetManager;
    }

    public d(InterfaceC4778e service) {
        this.a = 14;
        Intrinsics.checkNotNullParameter(service, "service");
        this.b = service;
    }

    public d(Braze braze) {
        this.a = 3;
        Intrinsics.checkNotNullParameter(braze, "braze");
        this.b = braze;
    }

    public d(com.quizlet.remote.service.j dynamicURLService) {
        this.a = 13;
        Intrinsics.checkNotNullParameter(dynamicURLService, "dynamicURLService");
        this.b = dynamicURLService;
    }

    public d(androidx.work.impl.model.c dataSource, com.quizlet.quizletandroid.ui.setcreation.adapters.a mapper) {
        this.a = 12;
        Intrinsics.checkNotNullParameter(dataSource, "dataSource");
        Intrinsics.checkNotNullParameter(mapper, "mapper");
        this.b = dataSource;
    }

    public d(com.quizlet.learn.logging.a learnEventLogger) {
        this.a = 10;
        Intrinsics.checkNotNullParameter(learnEventLogger, "learnEventLogger");
        this.b = learnEventLogger;
    }

    public d(InterfaceC4776c service) {
        this.a = 15;
        Intrinsics.checkNotNullParameter(service, "service");
        this.b = service;
    }

    public d(io.ktor.http.u encodedParametersBuilder) {
        this.a = 16;
        Intrinsics.checkNotNullParameter(encodedParametersBuilder, "encodedParametersBuilder");
        this.b = encodedParametersBuilder;
    }

    public d(com.quizlet.data.repository.login.a signUpValidationRepository) {
        this.a = 0;
        com.quizlet.qutils.string.c emailUtil = com.quizlet.qutils.string.c.a;
        Intrinsics.checkNotNullParameter(emailUtil, "emailUtil");
        Intrinsics.checkNotNullParameter(signUpValidationRepository, "signUpValidationRepository");
        this.b = signUpValidationRepository;
    }

    public d(com.quizlet.infra.legacysyncengine.managers.d loggedInUserManager) {
        this.a = 2;
        Intrinsics.checkNotNullParameter(loggedInUserManager, "loggedInUserManager");
        this.b = loggedInUserManager;
    }

    public d(com.quizlet.quizletandroid.ui.common.ads.prebid.g bannerAdManager) {
        this.a = 4;
        Intrinsics.checkNotNullParameter(bannerAdManager, "bannerAdManager");
        this.b = bannerAdManager;
    }

    public d(kotlinx.coroutines.channels.h hVar, kotlinx.coroutines.channels.b bVar) {
        this.a = 18;
        kotlinx.coroutines.channels.d dVar = kotlinx.coroutines.channels.d.a;
        kotlinx.coroutines.channels.e eVar = kotlinx.coroutines.channels.e.a;
        this.b = hVar;
    }
}

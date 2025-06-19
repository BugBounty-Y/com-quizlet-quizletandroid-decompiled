package androidx.compose.ui.platform;

import android.content.Context;
import android.content.Intent;
import androidx.fragment.app.AbstractC1136h0;
import com.comscore.streaming.EventType;
import com.google.android.gms.ads.nativead.NativeCustomFormatAd;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3206m6;
import com.google.android.gms.internal.mlkit_vision_camera.J1;
import com.google.firebase.perf.metrics.Trace;
import com.pubmatic.sdk.video.c;
import com.quizlet.ads.data.AdDataType;
import com.quizlet.data.model.Textbook;
import com.quizlet.db.data.models.persisted.fields.DBImageRefFields;
import com.quizlet.eventlogger.features.explanations.ExplanationsLogger;
import com.quizlet.eventlogger.features.search.SearchEventLogger;
import com.quizlet.eventlogger.features.search.SearchType;
import com.quizlet.features.setpage.SetPageActivity;
import com.quizlet.generated.enums.A1;
import com.quizlet.growthbook.QGrowthBookException;
import com.quizlet.quizletandroid.ui.login.SignUpWallModalFragment;
import com.quizlet.quizletandroid.ui.setcreation.activities.EditSetPermissionSelectionActivity;
import com.quizlet.quizletandroid.ui.setcreation.activities.InputPasswordActivity;
import com.quizlet.search.data.term.TermSearchUiModel;
import com.quizlet.search.viewmodels.AbstractC4797c;
import com.quizlet.search.viewmodels.C4796b;
import com.quizlet.search.viewmodels.C4799e;
import com.quizlet.search.viewmodels.C4804j;
import com.quizlet.uicommon.ui.common.dialogs.info.InfoDialogModalFragment;
import com.sdk.growthbook.GrowthBookSDK;
import com.sdk.growthbook.model.GBExperiment;
import com.sdk.growthbook.model.GBExperimentResult;
import com.sdk.growthbook.model.GBFeature;
import com.sdk.growthbook.model.GBFeatureRule;
import com.sdk.growthbook.utils.GBError;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import kotlin.Pair;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.C4956o;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.compose.ui.platform.p, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final /* synthetic */ class C0960p extends C4956o implements Function2 {
    public final /* synthetic */ int a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ C0960p(int i, Object obj, Class cls, String str, String str2, int i2, int i3) {
        super(i, i2, cls, obj, str, str2);
        this.a = i3;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        String errorMessage;
        Object next;
        int iB = 0;
        switch (this.a) {
            case 0:
                return Boolean.valueOf(C0971v.e((C0971v) this.receiver, (androidx.compose.ui.focus.c) obj, (androidx.compose.ui.geometry.c) obj2));
            case 1:
                ((androidx.credentials.playservices.controllers.a) this.receiver).getClass();
                return androidx.credentials.playservices.controllers.a.a((String) obj, (String) obj2);
            case 2:
                ((androidx.credentials.playservices.controllers.a) this.receiver).getClass();
                return androidx.credentials.playservices.controllers.a.a((String) obj, (String) obj2);
            case 3:
                ((com.amazon.aps.ads.util.adview.b) this.receiver).notifyViewabilityAndSetIsVisible(((Boolean) obj).booleanValue(), ((Boolean) obj2).booleanValue());
                return Unit.a;
            case 4:
                Textbook p0 = (Textbook) obj;
                int iIntValue = ((Number) obj2).intValue();
                Intrinsics.checkNotNullParameter(p0, "p0");
                com.quizlet.explanations.questiondetail.viewmodel.f fVar = (com.quizlet.explanations.questiondetail.viewmodel.f) this.receiver;
                fVar.getClass();
                long j = p0.a;
                String str = p0.b;
                ExplanationsLogger.b(fVar.g, new ExplanationsLogger.EventData.Textbook(j, str), iIntValue);
                fVar.y.j(new com.quizlet.explanations.questiondetail.data.h(str));
                return Unit.a;
            case 5:
                com.quizlet.qutils.string.g text = (com.quizlet.qutils.string.g) obj;
                com.quizlet.qutils.string.g title = (com.quizlet.qutils.string.g) obj2;
                Intrinsics.checkNotNullParameter(text, "p0");
                Intrinsics.checkNotNullParameter(title, "p1");
                com.quizlet.quizletandroid.ui.studymodes.flashcards.navigation.a aVar = (com.quizlet.quizletandroid.ui.studymodes.flashcards.navigation.a) this.receiver;
                aVar.getClass();
                Intrinsics.checkNotNullParameter(text, "text");
                Intrinsics.checkNotNullParameter(title, "title");
                String str2 = InfoDialogModalFragment.s;
                Context context = aVar.a;
                String title2 = title.a(context);
                String info = text.a(context);
                Intrinsics.checkNotNullParameter(title2, "title");
                Intrinsics.checkNotNullParameter(info, "info");
                InfoDialogModalFragment infoDialogModalFragment = new InfoDialogModalFragment();
                infoDialogModalFragment.setArguments(AbstractC3206m6.a(new Pair("title", title2), new Pair("info", info)));
                Intrinsics.e(context, "null cannot be cast to non-null type androidx.fragment.app.FragmentActivity");
                AbstractC1136h0 supportFragmentManager = ((androidx.fragment.app.I) context).getSupportFragmentManager();
                Intrinsics.checkNotNullExpressionValue(supportFragmentManager, "getSupportFragmentManager(...)");
                infoDialogModalFragment.O(supportFragmentManager, InfoDialogModalFragment.s);
                return Unit.a;
            case 6:
                com.quizlet.quizletandroid.ui.studymodes.flashcards.navigation.a aVar2 = (com.quizlet.quizletandroid.ui.studymodes.flashcards.navigation.a) this.receiver;
                aVar2.getClass();
                Intent intentB = com.quizlet.features.setpage.e.b(SetPageActivity.h1, aVar2.a, ((Number) obj).longValue(), (A1) obj2, null, null, null, false, null, 248);
                SignUpWallModalFragment signUpWallModalFragment = new SignUpWallModalFragment();
                signUpWallModalFragment.setArguments(AbstractC3206m6.a(new Pair("redirectIntent", intentB)));
                Context context2 = aVar2.a;
                Intrinsics.e(context2, "null cannot be cast to non-null type androidx.fragment.app.FragmentActivity");
                AbstractC1136h0 supportFragmentManager2 = ((androidx.fragment.app.I) context2).getSupportFragmentManager();
                Intrinsics.checkNotNullExpressionValue(supportFragmentManager2, "getSupportFragmentManager(...)");
                signUpWallModalFragment.O(supportFragmentManager2, SignUpWallModalFragment.X);
                return Unit.a;
            case 7:
                long jLongValue = ((Number) obj).longValue();
                List p1 = (List) obj2;
                Intrinsics.checkNotNullParameter(p1, "p1");
                ((com.quizlet.features.infra.folder.menu.viewmodel.n) this.receiver).f(jLongValue, p1);
                return Unit.a;
            case 8:
                com.quizlet.features.infra.folder.menu.data.b p02 = (com.quizlet.features.infra.folder.menu.data.b) obj;
                boolean zBooleanValue = ((Boolean) obj2).booleanValue();
                Intrinsics.checkNotNullParameter(p02, "p0");
                ((com.quizlet.features.infra.folder.menu.viewmodel.n) this.receiver).c(p02, zBooleanValue);
                return Unit.a;
            case 9:
                int iIntValue2 = ((Number) obj).intValue();
                String modelId = (String) obj2;
                Intrinsics.checkNotNullParameter(modelId, "p1");
                androidx.navigation.H h = (androidx.navigation.H) this.receiver;
                Intrinsics.checkNotNullParameter(h, "<this>");
                Intrinsics.checkNotNullParameter(modelId, "modelId");
                androidx.navigation.B bK = h.b.h().k("report_content");
                if (bK != null) {
                    h.b(bK.b.c, AbstractC3206m6.a(new Pair(DBImageRefFields.Names.MODEL_TYPE, Integer.valueOf(iIntValue2)), new Pair(DBImageRefFields.Names.MODEL_ID, modelId)), J1.c(new com.quizlet.features.notes.detail.navigation.c(iB, bK)));
                } else {
                    androidx.navigation.r.d(h, "report_content");
                }
                return Unit.a;
            case 10:
                String p03 = (String) obj;
                String p12 = (String) obj2;
                Intrinsics.checkNotNullParameter(p03, "p0");
                Intrinsics.checkNotNullParameter(p12, "p1");
                com.quizlet.features.practicetest.navigation.c.d((androidx.navigation.H) this.receiver, p03, p12);
                return Unit.a;
            case 11:
                String p04 = (String) obj;
                com.quizlet.features.infra.models.upgrade.a p13 = (com.quizlet.features.infra.models.upgrade.a) obj2;
                Intrinsics.checkNotNullParameter(p04, "p0");
                Intrinsics.checkNotNullParameter(p13, "p1");
                ((com.quizlet.features.practicetest.navigation.d) this.receiver).b(p04, p13);
                return Unit.a;
            case 12:
                com.quizlet.features.practicetest.navigation.c.b((androidx.navigation.H) this.receiver, (String) obj, (String) obj2);
                return Unit.a;
            case 13:
                String p05 = (String) obj;
                String p14 = (String) obj2;
                Intrinsics.checkNotNullParameter(p05, "p0");
                Intrinsics.checkNotNullParameter(p14, "p1");
                com.quizlet.features.practicetest.navigation.c.d((androidx.navigation.H) this.receiver, p05, p14);
                return Unit.a;
            case 14:
                int iIntValue3 = ((Number) obj).intValue();
                String p15 = (String) obj2;
                Intrinsics.checkNotNullParameter(p15, "p1");
                com.quizlet.features.practicetest.navigation.c.c((androidx.navigation.H) this.receiver, iIntValue3, p15);
                return Unit.a;
            case 15:
                String p06 = (String) obj;
                com.quizlet.features.infra.models.upgrade.a p16 = (com.quizlet.features.infra.models.upgrade.a) obj2;
                Intrinsics.checkNotNullParameter(p06, "p0");
                Intrinsics.checkNotNullParameter(p16, "p1");
                ((com.quizlet.features.practicetest.navigation.d) this.receiver).b(p06, p16);
                return Unit.a;
            case 16:
                com.quizlet.features.practicetest.navigation.c.b((androidx.navigation.H) this.receiver, (String) obj, (String) obj2);
                return Unit.a;
            case 17:
                int iIntValue4 = ((Number) obj).intValue();
                String p17 = (String) obj2;
                Intrinsics.checkNotNullParameter(p17, "p1");
                com.quizlet.features.practicetest.navigation.c.c((androidx.navigation.H) this.receiver, iIntValue4, p17);
                return Unit.a;
            case 18:
                String p07 = (String) obj;
                com.quizlet.features.infra.models.upgrade.a p18 = (com.quizlet.features.infra.models.upgrade.a) obj2;
                Intrinsics.checkNotNullParameter(p07, "p0");
                Intrinsics.checkNotNullParameter(p18, "p1");
                ((com.quizlet.features.practicetest.navigation.d) this.receiver).b(p07, p18);
                return Unit.a;
            case 19:
                GBExperiment p08 = (GBExperiment) obj;
                GBExperimentResult p19 = (GBExperimentResult) obj2;
                Intrinsics.checkNotNullParameter(p08, "p0");
                Intrinsics.checkNotNullParameter(p19, "p1");
                com.quizlet.growthbook.e eVar = (com.quizlet.growthbook.e) this.receiver;
                eVar.getClass();
                if (p19.getInExperiment()) {
                    kotlinx.coroutines.E.A(eVar.e, null, null, new com.quizlet.growthbook.b(eVar, new com.quizlet.data.model.V(p08.getKey(), String.valueOf(p19.getVariationId()), p19.getHashAttribute(), p19.getHashValue()), p08, p19, null), 3);
                }
                return Unit.a;
            case 20:
                boolean zBooleanValue2 = ((Boolean) obj).booleanValue();
                GBError gBError = (GBError) obj2;
                com.quizlet.growthbook.e eVar2 = (com.quizlet.growthbook.e) this.receiver;
                Trace trace = eVar2.j;
                if (trace != null) {
                    trace.stop();
                }
                if (zBooleanValue2) {
                    eVar2.i = true;
                    timber.log.c.a.a("GrowthBook cache refreshed", new Object[0]);
                    GrowthBookSDK growthBookSDK = eVar2.g;
                    if (growthBookSDK == null) {
                        Intrinsics.m("growthBookSDK");
                        throw null;
                    }
                    Map<String, GBFeature> features = growthBookSDK.getFeatures();
                    ArrayList arrayList = new ArrayList();
                    Iterator<Map.Entry<String, GBFeature>> it2 = features.entrySet().iterator();
                    while (it2.hasNext()) {
                        List<GBFeatureRule> rules = it2.next().getValue().getRules();
                        if (rules == null) {
                            rules = kotlin.collections.K.a;
                        }
                        kotlin.collections.G.u(arrayList, rules);
                    }
                    ArrayList arrayList2 = new ArrayList();
                    Iterator it3 = arrayList.iterator();
                    while (it3.hasNext()) {
                        String key = ((GBFeatureRule) it3.next()).getKey();
                        if (key != null) {
                            arrayList2.add(key);
                        }
                    }
                    kotlinx.coroutines.E.A(eVar2.e, null, null, new com.quizlet.growthbook.a(eVar2, arrayList2, null), 3);
                } else {
                    if (gBError == null || (errorMessage = gBError.getErrorMessage()) == null) {
                        errorMessage = "Unknown error";
                    }
                    QGrowthBookException qGrowthBookException = new QGrowthBookException(errorMessage);
                    String stackTrace = gBError != null ? gBError.getStackTrace() : null;
                    if (stackTrace != null && (kotlin.text.D.r(stackTrace, "java.net.UnknownHostException", false) || kotlin.text.D.r(stackTrace, "java.net.SocketTimeoutException", false) || kotlin.text.D.r(stackTrace, "java.net.SocketException", false) || kotlin.text.D.r(stackTrace, "javax.net.ssl.SSLException", false))) {
                        timber.log.c.a.c(qGrowthBookException, "Failed to refresh GrowthBook cache", new Object[0]);
                    } else {
                        timber.log.c.a.f(qGrowthBookException, "Failed to refresh GrowthBook cache", new Object[0]);
                    }
                }
                return Unit.a;
            case 21:
                NativeCustomFormatAd data = (NativeCustomFormatAd) obj;
                com.quizlet.ads.data.d key2 = (com.quizlet.ads.data.d) obj2;
                Intrinsics.checkNotNullParameter(data, "p0");
                Intrinsics.checkNotNullParameter(key2, "p1");
                com.quizlet.learn.ads.f fVar2 = (com.quizlet.learn.ads.f) this.receiver;
                fVar2.getClass();
                Intrinsics.checkNotNullParameter(data, "nativeAd");
                Intrinsics.checkNotNullParameter(key2, "key");
                com.quizlet.ads.g gVar = fVar2.e;
                gVar.getClass();
                Intrinsics.checkNotNullParameter(data, "data");
                gVar.a = data;
                com.quizlet.learn.ads.d dVar = fVar2.h;
                if (dVar != null) {
                    AdDataType.CustomAdType adDataType = new AdDataType.CustomAdType(key2);
                    Intrinsics.checkNotNullParameter(adDataType, "adDataType");
                    ((com.quizlet.learn.ads.h) dVar).d = adDataType;
                }
                return Unit.a;
            case EventType.WINDOW_STATE /* 22 */:
                String p09 = (String) obj;
                String p110 = (String) obj2;
                Intrinsics.checkNotNullParameter(p09, "p0");
                Intrinsics.checkNotNullParameter(p110, "p1");
                ((com.quizlet.quizletandroid.ui.navigationmanagers.d) this.receiver).d(p09, p110);
                return Unit.a;
            case EventType.AUDIO /* 23 */:
                String p010 = (String) obj;
                String p111 = (String) obj2;
                Intrinsics.checkNotNullParameter(p010, "p0");
                Intrinsics.checkNotNullParameter(p111, "p1");
                ((com.quizlet.quizletandroid.ui.navigationmanagers.d) this.receiver).d(p010, p111);
                return Unit.a;
            case EventType.VIDEO /* 24 */:
                com.quizlet.quizletandroid.util.j p011 = (com.quizlet.quizletandroid.util.j) obj;
                boolean zBooleanValue3 = ((Boolean) obj2).booleanValue();
                Intrinsics.checkNotNullParameter(p011, "p0");
                EditSetPermissionSelectionActivity context3 = (EditSetPermissionSelectionActivity) this.receiver;
                if (p011 == context3.q && !zBooleanValue3) {
                    context3.setResult(1234);
                    context3.finish();
                } else if (p011 != com.quizlet.quizletandroid.util.j.b) {
                    Intent intent = new Intent();
                    intent.putExtra("current_permission_access", p011.ordinal());
                    intent.putExtra("changing_set_visibility", context3.r);
                    context3.setResult(c.a.DEFAULT_MEDIA_URI_TIMEOUT, intent);
                    context3.finish();
                } else if (zBooleanValue3) {
                    String str3 = InputPasswordActivity.t;
                    Intrinsics.checkNotNullParameter(context3, "context");
                    context3.startActivityForResult(new Intent(context3, (Class<?>) InputPasswordActivity.class), c.a.DEFAULT_MEDIA_URI_TIMEOUT);
                } else {
                    Intent intent2 = new Intent();
                    intent2.putExtra("current_permission_access", p011.ordinal());
                    intent2.putExtra("changing_set_visibility", context3.r);
                    intent2.putExtra("has_changed_password_use", true);
                    context3.setResult(c.a.DEFAULT_MEDIA_URI_TIMEOUT, intent2);
                    context3.finish();
                    Intent intent3 = new Intent();
                    intent3.putExtra("current_permission_access", p011.ordinal());
                    intent3.putExtra("changing_set_visibility", context3.r);
                    context3.setResult(c.a.DEFAULT_MEDIA_URI_TIMEOUT, intent3);
                    context3.finish();
                }
                return Unit.a;
            case EventType.SUBS /* 25 */:
                int iIntValue5 = ((Number) obj).intValue();
                int iIntValue6 = ((Number) obj2).intValue();
                com.quizlet.quizletandroid.ui.subject.viewmodel.m mVar = (com.quizlet.quizletandroid.ui.subject.viewmodel.m) this.receiver;
                if (iIntValue6 > 0) {
                    mVar.getClass();
                    iB = kotlin.math.c.b((iIntValue5 / iIntValue6) * 100);
                }
                mVar.h = Math.min(Math.max(iB, mVar.h), 100);
                return Unit.a;
            case EventType.CDN /* 26 */:
                TermSearchUiModel termModel = (TermSearchUiModel) obj;
                int iIntValue7 = ((Number) obj2).intValue();
                Intrinsics.checkNotNullParameter(termModel, "p0");
                com.quizlet.search.viewmodels.p pVar = (com.quizlet.search.viewmodels.p) this.receiver;
                pVar.getClass();
                Intrinsics.checkNotNullParameter(termModel, "termModel");
                kotlinx.coroutines.E.A(androidx.lifecycle.p0.j(pVar), null, null, new com.quizlet.search.viewmodels.o(pVar, termModel, iIntValue7, null), 3);
                return Unit.a;
            case 27:
                SearchType searchType = (SearchType) obj;
                List listeners = (List) obj2;
                Intrinsics.checkNotNullParameter(listeners, "p1");
                com.quizlet.search.viewmodels.p pVar2 = (com.quizlet.search.viewmodels.p) this.receiver;
                pVar2.getClass();
                Intrinsics.checkNotNullParameter(listeners, "listeners");
                if (searchType != null) {
                    SearchEventLogger searchEventLogger = pVar2.f;
                    searchEventLogger.setCurrentSearchTab(searchType);
                    searchEventLogger.e();
                    Iterator it4 = listeners.iterator();
                    while (true) {
                        if (it4.hasNext()) {
                            next = it4.next();
                            if (((AbstractC4797c) next).A() == searchType) {
                            }
                        } else {
                            next = null;
                        }
                    }
                    AbstractC4797c abstractC4797c = (AbstractC4797c) next;
                    if (abstractC4797c != null) {
                        kotlinx.coroutines.E.A(androidx.lifecycle.p0.j(abstractC4797c), null, null, new C4796b(abstractC4797c, null), 3);
                    }
                }
                return Unit.a;
            case 28:
                long jLongValue2 = ((Number) obj).longValue();
                int iIntValue8 = ((Number) obj2).intValue();
                com.quizlet.search.viewmodels.p pVar3 = (com.quizlet.search.viewmodels.p) this.receiver;
                pVar3.getClass();
                kotlinx.coroutines.E.A(androidx.lifecycle.p0.j(pVar3), null, null, new C4799e(pVar3, jLongValue2, iIntValue8, null), 3);
                return Unit.a;
            default:
                long jLongValue3 = ((Number) obj).longValue();
                int iIntValue9 = ((Number) obj2).intValue();
                com.quizlet.search.viewmodels.p pVar4 = (com.quizlet.search.viewmodels.p) this.receiver;
                pVar4.getClass();
                kotlinx.coroutines.E.A(androidx.lifecycle.p0.j(pVar4), null, null, new C4804j(pVar4, jLongValue3, iIntValue9, null), 3);
                return Unit.a;
        }
    }
}

package com.quizlet.features.folders.composables;

import android.content.Context;
import android.content.Intent;
import android.content.IntentSender;
import android.content.res.AssetFileDescriptor;
import android.media.MediaPlayer;
import android.net.Uri;
import androidx.activity.result.ActivityResult;
import androidx.activity.result.IntentSenderRequest;
import androidx.compose.runtime.W0;
import androidx.coordinatorlayout.widget.CoordinatorLayout;
import androidx.navigation.C1284f;
import androidx.navigation.C1290l;
import com.braze.ui.contentcards.adapters.ContentCardAdapter;
import com.comscore.streaming.EventType;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3242q6;
import com.google.android.gms.internal.mlkit_vision_barcode.I6;
import com.google.android.gms.internal.mlkit_vision_document_scanner.D4;
import com.quizlet.api.model.ServerProvidedError;
import com.quizlet.data.model.m2;
import com.quizlet.db.data.models.base.BaseDBModel;
import com.quizlet.db.data.models.identity.ModelIdentityProvider;
import com.quizlet.eventlogger.model.OnboardingSurveyEventLog;
import com.quizlet.features.infra.studysetting.data.QuestionSettings;
import com.quizlet.features.notes.paywall.ScanNotesPaywallActivity;
import com.quizlet.features.questionnaire.navigation.Control;
import com.quizlet.features.settings.viewmodels.C4444b;
import com.quizlet.features.settings.viewmodels.C4449g;
import com.quizlet.features.settings.viewmodels.C4451i;
import com.quizlet.features.universaluploadflow.data.C4461j;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.ui.activitycenter.fragments.ActivityCenterContentCardsFragment;
import com.quizlet.quizletandroid.ui.activitycenter.fragments.ActivityCenterFragment;
import com.quizlet.quizletandroid.ui.activitycenter.fragments.ActivityCenterModalFragment;
import com.quizlet.quizletandroid.ui.base.ViewModelDataSourceRecyclerViewFragment;
import com.quizlet.quizletandroid.ui.globalnav.data.GlobalNavReroute;
import com.quizlet.quizletandroid.ui.startpage.nav2.OldHomeFragment;
import com.quizlet.upgrade.ui.activity.UpgradeActivity;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.flow.s0;

/* loaded from: classes3.dex */
public final /* synthetic */ class J implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public /* synthetic */ J(com.quizlet.offline.managers.i iVar, com.quizlet.offline.managers.a aVar) {
        this.a = 25;
        this.b = aVar;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        Object value;
        Object value2;
        Object value3;
        C1284f c1284f = androidx.navigation.S.k;
        com.google.android.material.snackbar.h hVarF = null;
        Object obj2 = this.b;
        switch (this.a) {
            case 0:
                ((Float) obj).floatValue();
                com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
                mVar.p();
                float f = 2;
                float f2 = com.quizlet.ui.resources.designsystem.generated.j.j * f;
                mVar.h();
                return Float.valueOf(((androidx.compose.ui.unit.b) obj2).c0(f2 + com.quizlet.ui.resources.designsystem.generated.h.g) * f);
            case 1:
                com.quizlet.features.infra.models.share.b it2 = (com.quizlet.features.infra.models.share.b) obj;
                Intrinsics.checkNotNullParameter(it2, "it");
                com.quizlet.features.folders.viewmodel.N n = (com.quizlet.features.folders.viewmodel.N) obj2;
                String url = it2.a;
                com.quizlet.features.folders.logging.e eVar = n.h;
                eVar.getClass();
                Intrinsics.checkNotNullParameter(url, "url");
                com.quizlet.utmhelper.a utmParams = it2.b;
                Intrinsics.checkNotNullParameter(utmParams, "utmParams");
                eVar.a.t(url, Long.valueOf(n.r), utmParams);
                return Unit.a;
            case 2:
                IntentSender intentSender = (IntentSender) obj;
                Intrinsics.checkNotNullParameter(intentSender, "it");
                Intrinsics.checkNotNullParameter(intentSender, "intentSender");
                ((androidx.activity.compose.o) obj2).a(new IntentSenderRequest(intentSender, null, 0, 0));
                return Unit.a;
            case 3:
                Intrinsics.checkNotNullParameter((Context) obj, "it");
                return (com.quizlet.themes.q) obj2;
            case 4:
                ActivityResult result = (ActivityResult) obj;
                Intrinsics.checkNotNullParameter(result, "result");
                if (result.a == -1) {
                    ((com.quizlet.features.notes.detail.viewmodels.v) obj2).F(com.quizlet.features.notes.common.events.t.a);
                }
                return Unit.a;
            case 5:
                com.quizlet.features.notes.paywall.e eVar2 = (com.quizlet.features.notes.paywall.e) obj;
                int i = ScanNotesPaywallActivity.k;
                Intrinsics.d(eVar2);
                ScanNotesPaywallActivity scanNotesPaywallActivity = (ScanNotesPaywallActivity) obj2;
                int iOrdinal = eVar2.ordinal();
                if (iOrdinal == 0) {
                    com.quizlet.quizletandroid.ui.navigationmanagers.f fVar = scanNotesPaywallActivity.j;
                    if (fVar == null) {
                        Intrinsics.m("navigationManager");
                        throw null;
                    }
                    String str = UpgradeActivity.v;
                    com.quizlet.features.infra.models.upgrade.a aVar = com.quizlet.features.infra.models.upgrade.a.u;
                    Context context = fVar.a;
                    Intent intentI = AbstractC3242q6.i(context, "notes_meter_exceeded", aVar);
                    intentI.setFlags(268435456);
                    context.startActivity(intentI);
                } else if (iOrdinal == 1) {
                    com.quizlet.quizletandroid.ui.navigationmanagers.f fVar2 = scanNotesPaywallActivity.j;
                    if (fVar2 == null) {
                        Intrinsics.m("navigationManager");
                        throw null;
                    }
                    GlobalNavReroute.Library library = GlobalNavReroute.Library.a;
                    Context context2 = fVar2.a;
                    Intent intentA = D4.a(context2, library);
                    intentA.setFlags(268435456);
                    context2.startActivity(intentA);
                } else if (iOrdinal != 2) {
                    throw new NoWhenBranchMatchedException();
                }
                scanNotesPaywallActivity.finish();
                return Unit.a;
            case 6:
                List it3 = (List) obj;
                Intrinsics.checkNotNullParameter(it3, "it");
                ((com.quizlet.features.notes.upload.viewmodels.k) obj2).N(new com.quizlet.features.notes.common.events.E(it3));
                return Unit.a;
            case 7:
                OnboardingSurveyEventLog.Payload createEvent = (OnboardingSurveyEventLog.Payload) obj;
                Intrinsics.checkNotNullParameter(createEvent, "$this$createEvent");
                createEvent.setOnboardingSurveySource(((com.quizlet.features.onboarding.survey.m) obj2).name());
                return Unit.a;
            case 8:
                C1290l navArgument = (C1290l) obj;
                Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                navArgument.a.a = true;
                navArgument.b(androidx.navigation.S.n);
                navArgument.a(((com.quizlet.features.practicetest.navigation.e) obj2).a);
                return Unit.a;
            case 9:
                Control.Button option = (Control.Button) obj;
                Intrinsics.checkNotNullParameter(option, "option");
                String payload = option.e;
                com.quizlet.features.questionnaire.steps.b bVar = (com.quizlet.features.questionnaire.steps.b) obj2;
                bVar.getClass();
                Intrinsics.checkNotNullParameter(payload, "payload");
                com.quizlet.data.interactor.course.a aVar2 = bVar.c;
                aVar2.getClass();
                Intrinsics.checkNotNullParameter(payload, "payload");
                ((com.quizlet.usecase.a) ((com.quizlet.usecase.b) aVar2.b)).a(new com.quizlet.features.questionnaire.navigation.o(payload, option.c));
                return Unit.a;
            case 10:
                String it4 = (String) obj;
                Intrinsics.checkNotNullParameter(it4, "it");
                ((com.quizlet.features.questiontypes.fitb.m) obj2).A(new com.quizlet.features.questiontypes.fitb.q(it4));
                return Unit.a;
            case 11:
                com.quizlet.diagrams.f it5 = (com.quizlet.diagrams.f) obj;
                Intrinsics.checkNotNullParameter(it5, "it");
                ((com.quizlet.features.questiontypes.mcq.l) obj2).B(new com.quizlet.features.questiontypes.mcq.s(it5));
                return Unit.a;
            case 12:
                ((com.quizlet.features.questiontypes.mcq.l) ((com.quizlet.features.questiontypes.mcq.a) obj2)).B(new com.quizlet.features.questiontypes.mcq.q(((Integer) obj).intValue()));
                return Unit.a;
            case 13:
                androidx.compose.ui.graphics.S graphicsLayer = (androidx.compose.ui.graphics.S) obj;
                Intrinsics.checkNotNullParameter(graphicsLayer, "$this$graphicsLayer");
                graphicsLayer.b(((Number) ((W0) obj2).getValue()).floatValue());
                return Unit.a;
            case 14:
                com.quizlet.features.setpage.progress.b progressData = (com.quizlet.features.setpage.progress.b) obj;
                Intrinsics.checkNotNullParameter(progressData, "progressData");
                ((com.quizlet.features.setpage.progress.presentation.viewmodel.a) obj2).h.j(progressData);
                return Unit.a;
            case 15:
                ServerProvidedError serverProvidedError = (ServerProvidedError) obj;
                s0 s0Var = ((C4444b) obj2).f;
                do {
                    value = s0Var.getValue();
                } while (!s0Var.k(value, new com.quizlet.features.settings.data.states.a(new com.quizlet.features.settings.data.models.g(serverProvidedError))));
                return Unit.a;
            case 16:
                ServerProvidedError serverProvidedError2 = (ServerProvidedError) obj;
                s0 s0Var2 = ((C4449g) obj2).f;
                do {
                    value2 = s0Var2.getValue();
                } while (!s0Var2.k(value2, new com.quizlet.features.settings.data.states.i(new com.quizlet.features.settings.data.models.g(serverProvidedError2))));
                return Unit.a;
            case 17:
                ServerProvidedError serverProvidedError3 = (ServerProvidedError) obj;
                s0 s0Var3 = ((C4451i) obj2).g;
                do {
                    value3 = s0Var3.getValue();
                } while (!s0Var3.k(value3, new com.quizlet.features.settings.data.states.e(new com.quizlet.features.settings.data.models.g(serverProvidedError3), null, null, 6)));
                return Unit.a;
            case 18:
                List it6 = (List) obj;
                Intrinsics.checkNotNullParameter(it6, "it");
                ArrayList arrayList = new ArrayList(kotlin.collections.C.q(it6, 10));
                Iterator it7 = it6.iterator();
                while (it7.hasNext()) {
                    String string = ((Uri) it7.next()).toString();
                    Intrinsics.checkNotNullExpressionValue(string, "toString(...)");
                    arrayList.add(string);
                }
                ((com.quizlet.features.universaluploadflow.viewmodel.g) ((com.quizlet.features.universaluploadflow.viewmodel.a) obj2)).D(new C4461j(arrayList));
                return Unit.a;
            case 19:
                C1290l navArgument2 = (C1290l) obj;
                Intrinsics.checkNotNullParameter(navArgument2, "$this$navArgument");
                navArgument2.a.a = false;
                navArgument2.b(new androidx.navigation.O(m2.class));
                navArgument2.a(((com.quizlet.features.universaluploadflow.navigation.h) obj2).a);
                return Unit.a;
            case 20:
                ((Float) obj).getClass();
                com.google.firebase.crashlytics.internal.common.i iVar = (com.google.firebase.crashlytics.internal.common.i) obj2;
                if (iVar != null) {
                    iVar.run();
                }
                return Unit.a;
            case 21:
                List list = com.quizlet.learn.viewmodel.G.D1;
                Intrinsics.checkNotNullParameter((com.quizlet.features.infra.basestudy.data.models.dataproviders.a) obj, "it");
                com.quizlet.learn.viewmodel.G g = (com.quizlet.learn.viewmodel.G) obj2;
                QuestionSettings questionSettingsA = QuestionSettings.a(g.I(), null, null, false, false, false, false, false, false, false, null, Long.valueOf(new Date().getTime()), false, false, false, false, false, 261119);
                com.quizlet.features.infra.studysetting.data.c dVar = g.c1 == 1 ? new retrofit2.adapter.rxjava3.d(27) : com.quizlet.features.infra.studysetting.data.b.a;
                com.quizlet.features.infra.basestudy.manager.f fVar3 = g.Z;
                QuestionSettings questionSettingsD = dVar.d(questionSettingsA, fVar3.g());
                QuestionSettings questionSettingsC = fVar3.g().c();
                long startTimestampMilliSec = g.M().getStartTimestampMilliSec();
                Long l = questionSettingsA.k;
                boolean z = (l == null || l.longValue() == startTimestampMilliSec) ? false : true;
                boolean z2 = questionSettingsC.c != questionSettingsA.c;
                fVar3.g().l(questionSettingsD);
                if (z) {
                    g.U(l, true);
                } else {
                    g.B.getClass();
                    if (com.google.android.gms.internal.mlkit_common.u.j(questionSettingsC, questionSettingsD, false)) {
                        com.quizlet.learn.viewmodel.G.G(g, true, 3);
                    }
                }
                g.e.a(g.M());
                if (z2) {
                    g.X.j(Boolean.valueOf(questionSettingsD.c));
                }
                return Unit.a;
            case EventType.WINDOW_STATE /* 22 */:
                List<BaseDBModel> models = (List) obj;
                Intrinsics.checkNotNullParameter(models, "localModels");
                com.quizlet.local.ormlite.models.bookmark.a aVar3 = (com.quizlet.local.ormlite.models.bookmark.a) obj2;
                com.onetrust.otpublishers.headless.UI.fragment.q qVar = (com.onetrust.otpublishers.headless.UI.fragment.q) aVar3.d;
                Intrinsics.checkNotNullParameter(qVar, "<this>");
                Intrinsics.checkNotNullParameter(models, "models");
                ModelIdentityProvider modelIdentityProvider = (ModelIdentityProvider) aVar3.b;
                Intrinsics.checkNotNullParameter(modelIdentityProvider, "modelIdentityProvider");
                for (BaseDBModel baseDBModel : models) {
                }
                io.reactivex.rxjava3.internal.operators.single.g gVarE = modelIdentityProvider.generateLocalIdsIfNeededAsync(models).e(new com.google.firebase.messaging.p(qVar, 28));
                Intrinsics.checkNotNullExpressionValue(gVarE, "flatMap(...)");
                return gVarE;
            case EventType.AUDIO /* 23 */:
                C1290l navArgument3 = (C1290l) obj;
                Intrinsics.checkNotNullParameter(navArgument3, "$this$navArgument");
                navArgument3.b(c1284f);
                navArgument3.a.a = false;
                navArgument3.a(Boolean.valueOf(((com.quizlet.login.common.navigation.l) obj2).a));
                return Unit.a;
            case EventType.VIDEO /* 24 */:
                C1290l navArgument4 = (C1290l) obj;
                Intrinsics.checkNotNullParameter(navArgument4, "$this$navArgument");
                navArgument4.b(c1284f);
                navArgument4.a.a = false;
                navArgument4.a(Boolean.valueOf(((com.quizlet.login.common.navigation.n) obj2).a));
                return Unit.a;
            case EventType.SUBS /* 25 */:
                Boolean isConnected = (Boolean) obj;
                Intrinsics.checkNotNullParameter(isConnected, "isConnected");
                boolean zBooleanValue = isConnected.booleanValue();
                OldHomeFragment oldHomeFragment = (OldHomeFragment) ((com.quizlet.offline.managers.a) obj2);
                CoordinatorLayout coordinatorLayout = oldHomeFragment.y;
                if (coordinatorLayout != null) {
                    com.google.android.material.snackbar.h hVar = oldHomeFragment.c1;
                    if (!zBooleanValue && (hVar == null || !hVar.b())) {
                        String string2 = coordinatorLayout.getContext().getString(R.string.offline_snackbar_msg);
                        Intrinsics.checkNotNullExpressionValue(string2, "getString(...)");
                        hVarF = I6.f(coordinatorLayout, string2);
                        hVarF.i();
                    } else if (!zBooleanValue || hVar == null) {
                        hVarF = hVar;
                    } else {
                        hVar.a(3);
                    }
                    oldHomeFragment.c1 = hVarF;
                }
                return Unit.a;
            case EventType.CDN /* 26 */:
                MediaPlayer mediaPlayer = (MediaPlayer) obj;
                mediaPlayer.reset();
                AssetFileDescriptor assetFileDescriptor = (AssetFileDescriptor) obj2;
                mediaPlayer.setDataSource(assetFileDescriptor.getFileDescriptor(), assetFileDescriptor.getStartOffset(), assetFileDescriptor.getLength());
                mediaPlayer.prepare();
                mediaPlayer.setLooping(true);
                mediaPlayer.start();
                return Unit.a;
            case 27:
                Integer num = (Integer) obj;
                String str2 = ActivityCenterContentCardsFragment.j;
                ContentCardAdapter contentCardAdapter = ((ActivityCenterContentCardsFragment) obj2).cardAdapter;
                if (contentCardAdapter != null) {
                    Intrinsics.d(num);
                    contentCardAdapter.notifyItemChanged(num.intValue());
                }
                return Unit.a;
            case 28:
                com.quizlet.quizletandroid.ui.activitycenter.fragments.c cVar = ((ActivityCenterFragment) obj2).l;
                if (cVar != null) {
                    ((ActivityCenterModalFragment) cVar).H(false, false);
                }
                return Unit.a;
            default:
                com.quizlet.infra.legacysyncengine.net.request.c cVar2 = (com.quizlet.infra.legacysyncengine.net.request.c) obj;
                Intrinsics.d(cVar2);
                ViewModelDataSourceRecyclerViewFragment viewModelDataSourceRecyclerViewFragment = (ViewModelDataSourceRecyclerViewFragment) obj2;
                com.google.android.material.internal.q qVar2 = viewModelDataSourceRecyclerViewFragment.l;
                qVar2.c = cVar2.b() && viewModelDataSourceRecyclerViewFragment.a0();
                qVar2.a();
                viewModelDataSourceRecyclerViewFragment.Y(cVar2);
                return Unit.a;
        }
    }

    public /* synthetic */ J(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }
}

package com.quizlet.features.setpage;

import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.content.res.Resources;
import android.os.Build;
import android.os.Bundle;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowManager;
import android.widget.FrameLayout;
import androidx.compose.ui.node.B;
import androidx.compose.ui.platform.ComposeView;
import androidx.fragment.app.AbstractC1136h0;
import androidx.fragment.app.C1121a;
import androidx.fragment.app.Fragment;
import androidx.lifecycle.p0;
import com.google.android.gms.internal.measurement.AbstractC3053s1;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3110c0;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3170i6;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3206m6;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3242q6;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3266t5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3675m6;
import com.google.android.gms.internal.mlkit_vision_document_scanner.D4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.S5;
import com.google.android.gms.measurement.internal.J;
import com.onetrust.otpublishers.headless.Public.OTUIDisplayReason.OTUIDisplayReasonCode;
import com.quizlet.db.data.models.persisted.DBStudySet;
import com.quizlet.db.data.models.persisted.fields.DBUserFields;
import com.quizlet.features.achievements.achievement.AchievementEarnedView;
import com.quizlet.features.blocks.GamesActivity;
import com.quizlet.features.flashcards.FlashcardsActivity;
import com.quizlet.features.infra.basestudy.data.models.t;
import com.quizlet.features.infra.basestudy.data.models.v;
import com.quizlet.features.infra.models.studymodeshared.StudyableModelData;
import com.quizlet.features.setpage.progress.presentation.ui.SetPageProgressFragment;
import com.quizlet.features.setpage.screenstates.A;
import com.quizlet.features.setpage.screenstates.C;
import com.quizlet.features.setpage.screenstates.C4421a;
import com.quizlet.features.setpage.screenstates.C4422b;
import com.quizlet.features.setpage.screenstates.C4423c;
import com.quizlet.features.setpage.screenstates.C4424d;
import com.quizlet.features.setpage.screenstates.C4425e;
import com.quizlet.features.setpage.screenstates.C4426f;
import com.quizlet.features.setpage.screenstates.D;
import com.quizlet.features.setpage.screenstates.w;
import com.quizlet.features.setpage.screenstates.x;
import com.quizlet.features.setpage.screenstates.y;
import com.quizlet.features.setpage.screenstates.z;
import com.quizlet.features.setpage.termlist.TermListComposeFragment;
import com.quizlet.features.setpage.viewmodel.L;
import com.quizlet.features.setpage.viewmodel.P;
import com.quizlet.generated.enums.A1;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.ui.globalnav.data.GlobalNavReroute;
import com.quizlet.quizletandroid.ui.login.SignUpWallModalFragment;
import com.quizlet.quizletandroid.ui.profile.ProfileActivity;
import com.quizlet.quizletandroid.ui.setcreation.activities.EditSetActivity;
import com.quizlet.quizletandroid.ui.setpage.addset.AddSetToClassActivity;
import com.quizlet.quizletandroid.ui.setpage.terms.TermListFragment;
import com.quizlet.quizletandroid.ui.studymodes.assistant.LearningAssistantActivity;
import com.quizlet.quizletandroid.ui.studymodes.match.activity.MatchActivity;
import com.quizlet.quizletandroid.ui.studymodes.testmode.activities.TestStudyModeActivity;
import com.quizlet.uicommon.ui.common.dialogs.ConfirmationModalFragment;
import com.quizlet.uicommon.ui.common.dialogs.QAlertDialogFragment;
import com.quizlet.uicommon.ui.common.dialogs.e;
import com.quizlet.uicommon.ui.common.overflowmenu.FullscreenOverflowFragment;
import com.quizlet.upgrade.ui.activity.UpgradeActivity;
import com.quizlet.upgrade.upsell.ui.UpsellModalFragment;
import java.util.List;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Pair;
import kotlin.Unit;
import kotlin.collections.K;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt__StringsKt;
import kotlin.u;
import kotlinx.coroutines.E;
import kotlinx.coroutines.flow.X;
import kotlinx.coroutines.flow.s0;
import kotlinx.coroutines.y0;

/* loaded from: classes3.dex */
public final /* synthetic */ class g implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ r b;

    public /* synthetic */ g(r rVar, int i) {
        this.a = i;
        this.b = rVar;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) throws Resources.NotFoundException {
        String webUrl;
        String str;
        s0 s0Var;
        Object value;
        String str2;
        webUrl = "";
        C c = C.a;
        int i = 3;
        final int i2 = 1;
        final r activity = this.b;
        switch (this.a) {
            case 0:
                com.quizlet.features.infra.snackbar.a aVar = (com.quizlet.features.infra.snackbar.a) obj;
                if (aVar instanceof com.quizlet.features.infra.snackbar.l) {
                    com.quizlet.features.infra.snackbar.l lVar = (com.quizlet.features.infra.snackbar.l) aVar;
                    lVar.getClass();
                    String message = lVar.c.a(activity);
                    if (message != null) {
                        com.quizlet.qutils.string.g gVar = lVar.d;
                        String strA = gVar != null ? gVar.a(activity) : null;
                        View view = ((com.quizlet.features.setpage.databinding.a) activity.K()).o;
                        Intrinsics.checkNotNullExpressionValue(view, "snackbarAnchor");
                        com.quizlet.features.infra.snackbar.k kVar = lVar.a;
                        Intrinsics.checkNotNullParameter(view, "view");
                        Intrinsics.checkNotNullParameter(message, "message");
                        com.google.android.material.snackbar.h hVarA = kVar.a(view, message, new com.braze.ui.inappmessage.f(17));
                        hVarA.k = lVar.b;
                        if (strA != null) {
                            hVarA.h(strA, new com.braze.ui.inappmessage.d(lVar, 27));
                        }
                        hVarA.i();
                    }
                } else if (!(aVar instanceof com.quizlet.features.infra.snackbar.m)) {
                    throw new NoWhenBranchMatchedException();
                }
                return Unit.a;
            case 1:
                if (((Boolean) obj).booleanValue()) {
                    AbstractC1136h0 supportFragmentManager = activity.getSupportFragmentManager();
                    String str3 = SetPageProgressFragment.l;
                    Fragment fragmentE = supportFragmentManager.E(str3);
                    if ((fragmentE instanceof SetPageProgressFragment ? (SetPageProgressFragment) fragmentE : null) == null) {
                        AbstractC1136h0 supportFragmentManager2 = activity.getSupportFragmentManager();
                        C1121a c1121aB = B.b(supportFragmentManager2, supportFragmentManager2);
                        c1121aB.l(R.id.set_progress_fragment_container, new SetPageProgressFragment(), str3);
                        c1121aB.g();
                    }
                }
                return Unit.a;
            case 2:
                ((com.quizlet.features.achievements.notification.f) activity.I.getValue()).A();
                return Unit.a;
            case 3:
                com.quizlet.features.achievements.notification.c cVar = (com.quizlet.features.achievements.notification.c) obj;
                if (cVar instanceof com.quizlet.features.achievements.notification.a) {
                    ((AchievementEarnedView) activity.v.getValue()).g(((com.quizlet.features.achievements.notification.a) cVar).a);
                } else {
                    if (!Intrinsics.b(cVar, com.quizlet.features.achievements.notification.b.a)) {
                        throw new NoWhenBranchMatchedException();
                    }
                    P pR = activity.R();
                    com.quizlet.data.repository.searchexplanations.c cVar2 = pR.C.a;
                    Context context = (Context) cVar2.c;
                    Intrinsics.checkNotNullParameter(context, "context");
                    PackageManager packageManager = context.getPackageManager();
                    String str4 = (Build.VERSION.SDK_INT >= 33 ? packageManager.getPackageInfo(context.getPackageName(), PackageManager.PackageInfoFlags.of(128L)) : packageManager.getPackageInfo(context.getPackageName(), 128)).versionName;
                    if (str4 == null || (str = (String) StringsKt__StringsKt.split$default(str4, new String[]{"."}, false, 0, 6, null).get(1)) == null) {
                        str = "";
                    }
                    if (!str.equals(((SharedPreferences) cVar2.b).getString("APP_VERSION_KEY", ""))) {
                        E.A(p0.j(pR), pR.B.plus(pR.O1), null, new L(pR, null), 2);
                    }
                }
                return Unit.a;
            case 4:
                Long l = (Long) obj;
                Intrinsics.d(l);
                long jLongValue = l.longValue();
                activity.P();
                Intrinsics.checkNotNullParameter(activity, "activity");
                Intent intentA = D4.a(activity, new GlobalNavReroute.AchievementsProfile(jLongValue, null));
                intentA.setFlags(268468224);
                activity.startActivity(intentA);
                return Unit.a;
            case 5:
                Boolean bool = (Boolean) obj;
                Intrinsics.d(bool);
                boolean zBooleanValue = bool.booleanValue();
                FrameLayout setSelectedTermsModeFragmentContainer = ((com.quizlet.features.setpage.databinding.a) activity.K()).f;
                Intrinsics.checkNotNullExpressionValue(setSelectedTermsModeFragmentContainer, "setSelectedTermsModeFragmentContainer");
                setSelectedTermsModeFragmentContainer.setVisibility(zBooleanValue ? 8 : 0);
                Intrinsics.checkNotNullParameter(activity, "<this>");
                if (!activity.isFinishing() && !activity.getSupportFragmentManager().R()) {
                    activity.Q();
                    AbstractC1136h0 fragmentManager = activity.getSupportFragmentManager();
                    Intrinsics.checkNotNullExpressionValue(fragmentManager, "getSupportFragmentManager(...)");
                    long jD = activity.R().D();
                    Intrinsics.checkNotNullParameter(fragmentManager, "fragmentManager");
                    if (zBooleanValue) {
                        String str5 = TermListComposeFragment.m;
                        androidx.savedstate.f fVarE = fragmentManager.E(str5);
                        if ((fVarE instanceof com.quizlet.features.setpage.termlist.contracts.a ? (com.quizlet.features.setpage.termlist.contracts.a) fVarE : null) == null) {
                            TermListComposeFragment termListComposeFragment = new TermListComposeFragment();
                            Bundle bundle = new Bundle();
                            bundle.putLong("setId", jD);
                            termListComposeFragment.setArguments(bundle);
                            C1121a c1121a = new C1121a(fragmentManager);
                            c1121a.l(R.id.term_list_fragment_container, termListComposeFragment, str5);
                            c1121a.g();
                        }
                    } else {
                        String str6 = TermListFragment.H;
                        androidx.savedstate.f fVarE2 = fragmentManager.E(str6);
                        if ((fVarE2 instanceof com.quizlet.features.setpage.termlist.contracts.a ? (com.quizlet.features.setpage.termlist.contracts.a) fVarE2 : null) == null) {
                            TermListFragment termListFragment = new TermListFragment();
                            Bundle bundle2 = new Bundle();
                            bundle2.putLong("setId", jD);
                            termListFragment.setArguments(bundle2);
                            C1121a c1121a2 = new C1121a(fragmentManager);
                            c1121a2.l(R.id.term_list_fragment_container, termListFragment, str6);
                            c1121a2.g();
                        }
                    }
                }
                return Unit.a;
            case 6:
                activity.getClass();
                return Unit.a;
            case 7:
                com.quizlet.features.setpage.screenstates.r rVar = (com.quizlet.features.setpage.screenstates.r) obj;
                if (rVar instanceof com.quizlet.features.setpage.screenstates.q) {
                    activity.V(true);
                } else {
                    if (!(rVar instanceof com.quizlet.features.setpage.screenstates.p)) {
                        throw new NoWhenBranchMatchedException();
                    }
                    activity.V(false);
                }
                return Unit.a;
            case 8:
                com.quizlet.features.setpage.screenstates.o oVar = (com.quizlet.features.setpage.screenstates.o) obj;
                if (oVar instanceof com.quizlet.features.setpage.screenstates.n) {
                    activity.I(true);
                } else {
                    if (!(oVar instanceof com.quizlet.features.setpage.screenstates.m)) {
                        throw new NoWhenBranchMatchedException();
                    }
                    activity.I(false);
                }
                return Unit.a;
            case 9:
                A a = (A) obj;
                boolean z = a instanceof z;
                final r rVar2 = this.b;
                if (z) {
                    z zVar = (z) a;
                    Intent intentB = new com.quizlet.features.setpage.utils.links.b(rVar2, zVar.a, zVar.b, zVar.c, zVar.d, null, zVar.f).b(zVar.g);
                    if (intentB != null) {
                        rVar2.startActivity(intentB);
                    }
                } else if (a instanceof x) {
                    DBStudySet dBStudySet = ((x) a).a;
                    Intent intent = rVar2.getIntent();
                    intent.removeExtra("shouldGoToEditSet");
                    rVar2.setIntent(intent);
                    com.quizlet.features.setpage.utils.setpermissions.a aVar2 = rVar2.x;
                    if (aVar2 == null) {
                        Intrinsics.m("permissionsViewUtil");
                        throw null;
                    }
                    io.reactivex.rxjava3.internal.operators.completable.a aVarB = ((com.quizlet.features.setpage.utils.setpermissions.f) aVar2).b(dBStudySet, rVar2, true, R.string.no_password_edit_exception, R.string.edit_set_exception, new g(rVar2, 14), null);
                    io.reactivex.rxjava3.functions.d dVar = new io.reactivex.rxjava3.functions.d() { // from class: com.quizlet.features.setpage.l
                        @Override // io.reactivex.rxjava3.functions.d
                        public final void accept(Object obj2) {
                            switch (i) {
                                case 0:
                                    io.reactivex.rxjava3.disposables.b disposable = (io.reactivex.rxjava3.disposables.b) obj2;
                                    Intrinsics.checkNotNullParameter(disposable, "p0");
                                    com.quizlet.quizletandroid.ui.base.g gVar2 = rVar2.e;
                                    gVar2.getClass();
                                    Intrinsics.checkNotNullParameter(disposable, "disposable");
                                    com.quizlet.baseui.managers.b bVar = gVar2.c;
                                    Intrinsics.checkNotNullParameter(disposable, "disposable");
                                    Object value2 = bVar.b.getValue();
                                    Intrinsics.checkNotNullExpressionValue(value2, "getValue(...)");
                                    ((io.reactivex.rxjava3.disposables.a) value2).b(disposable);
                                    break;
                                default:
                                    io.reactivex.rxjava3.disposables.b p0 = (io.reactivex.rxjava3.disposables.b) obj2;
                                    Intrinsics.checkNotNullParameter(p0, "p0");
                                    rVar2.y(p0);
                                    break;
                            }
                        }
                    };
                    com.quizlet.infra.legacysyncengine.net.request.g gVar2 = io.reactivex.rxjava3.internal.functions.d.d;
                    io.reactivex.rxjava3.internal.functions.b bVar = io.reactivex.rxjava3.internal.functions.d.c;
                    new io.reactivex.rxjava3.internal.operators.completable.i(aVarB, dVar, gVar2, bVar, bVar).e();
                } else if (a instanceof w) {
                    e.a aVar3 = new e.a(rVar2);
                    aVar3.c(R.string.delete_set_confirmation);
                    aVar3.b = true;
                    aVar3.e(R.string.delete_dialog_button, new j(rVar2, 4));
                    aVar3.d(R.string.cancel_dialog_button, null);
                    rVar2.G(aVar3.b());
                } else {
                    if (!(a instanceof y)) {
                        throw new NoWhenBranchMatchedException();
                    }
                    e.a aVar4 = new e.a(rVar2);
                    aVar4.d = AbstractC3053s1.e(((y) a).a, rVar2);
                    aVar4.c(R.string.set_page_progress_reset_confirm_desc);
                    aVar4.e(R.string.set_page_progress_reset, new j(rVar2, 1));
                    aVar4.d(R.string.cancel_dialog_button, new j(rVar2, 2));
                    aVar4.b = true;
                    rVar2.G(aVar4.b());
                }
                return Unit.a;
            case 10:
                com.quizlet.uicommon.ui.common.overflowmenu.i iVar = (com.quizlet.uicommon.ui.common.overflowmenu.i) activity.J.getValue();
                X listState = ((com.quizlet.features.setpage.screenstates.l) obj).a;
                iVar.getClass();
                Intrinsics.checkNotNullParameter(listState, "listState");
                do {
                    s0Var = iVar.b;
                    value = s0Var.getValue();
                } while (!s0Var.k(value, K.a));
                y0 y0Var = iVar.c;
                if (y0Var != null) {
                    y0Var.j(null);
                }
                iVar.c = E.A(p0.j(iVar), null, null, new com.quizlet.uicommon.ui.common.overflowmenu.h(listState, iVar, null), 3);
                new FullscreenOverflowFragment().O(activity.getSupportFragmentManager(), "STUDY_MODE_OVERFLOW_TAG");
                return Unit.a;
            case 11:
                com.quizlet.features.setpage.studypreview.data.b bVar2 = (com.quizlet.features.setpage.studypreview.data.b) obj;
                com.quizlet.features.setpage.studypreview.g gVar3 = (com.quizlet.features.setpage.studypreview.g) activity.K.getValue();
                Intrinsics.d(bVar2);
                gVar3.C(new com.quizlet.features.setpage.studypreview.m(bVar2));
                return Unit.a;
            case 12:
                boolean zBooleanValue2 = ((Boolean) obj).booleanValue();
                u uVar = activity.m;
                u uVar2 = activity.n;
                if (zBooleanValue2) {
                    Object value2 = uVar2.getValue();
                    Intrinsics.checkNotNullExpressionValue(value2, "getValue(...)");
                    ((ViewGroup) value2).setVisibility(0);
                    ((ComposeView) uVar.getValue()).setVisibility(4);
                } else {
                    Object value3 = uVar2.getValue();
                    Intrinsics.checkNotNullExpressionValue(value3, "getValue(...)");
                    ((ViewGroup) value3).setVisibility(8);
                    ((ComposeView) uVar.getValue()).setVisibility(0);
                }
                return Unit.a;
            case 13:
                boolean zBooleanValue3 = ((Boolean) obj).booleanValue();
                P pR2 = activity.R();
                if (zBooleanValue3) {
                    pR2.I1.d();
                }
                pR2.C1 = false;
                pR2.k1.j(c);
                return Unit.a;
            case 14:
                Boolean bool2 = (Boolean) obj;
                bool2.booleanValue();
                P pR3 = activity.R();
                pR3.getClass();
                timber.log.c.a.g("Editing set: %s (access is new? %s)", Long.valueOf(pR3.D()), bool2);
                pR3.H(new com.quizlet.features.setpage.viewmodel.x(pR3, null));
                return Unit.a;
            case 15:
                com.quizlet.features.setpage.shareset.a setPageAdsState = (com.quizlet.features.setpage.shareset.a) obj;
                Intrinsics.d(setPageAdsState);
                ((ComposeView) activity.m.getValue()).setContent(new androidx.compose.runtime.internal.d(true, -1704773662, new com.quizlet.assembly.compose.cards.c(activity, 16)));
                com.quizlet.data.interactor.set.c cVarQ = activity.Q();
                P setPageViewModel = activity.R();
                androidx.lifecycle.C lifeCycle = activity.getLifecycle();
                androidx.lifecycle.E lifecycleCoroutineScope = p0.h(activity);
                WindowManager windowManager = activity.getWindowManager();
                Intrinsics.checkNotNullExpressionValue(windowManager, "getWindowManager(...)");
                Object value4 = activity.n.getValue();
                Intrinsics.checkNotNullExpressionValue(value4, "getValue(...)");
                ViewGroup adContainer = (ViewGroup) value4;
                Intrinsics.checkNotNullParameter(setPageViewModel, "setPageViewModel");
                Intrinsics.checkNotNullParameter(setPageAdsState, "setPageAdsState");
                Intrinsics.checkNotNullParameter(lifeCycle, "lifeCycle");
                Intrinsics.checkNotNullParameter(lifecycleCoroutineScope, "lifecycleCoroutineScope");
                Intrinsics.checkNotNullParameter(windowManager, "windowManager");
                Intrinsics.checkNotNullParameter(adContainer, "adContainer");
                E.A(lifecycleCoroutineScope, null, null, new com.quizlet.quizletandroid.ui.setpage.e(cVarQ, lifeCycle, windowManager, setPageAdsState, adContainer, setPageViewModel, null), 3);
                com.quizlet.data.interactor.set.c cVarQ2 = activity.Q();
                androidx.lifecycle.C lifeCycle2 = activity.getLifecycle();
                androidx.lifecycle.E lifecycleCoroutineScope2 = p0.h(activity);
                WindowManager windowManager2 = activity.getWindowManager();
                Intrinsics.checkNotNullExpressionValue(windowManager2, "getWindowManager(...)");
                boolean zI = AbstractC3170i6.i(activity);
                ViewGroup footerBannerAdContainer = activity.O();
                Intrinsics.checkNotNullParameter(setPageAdsState, "setPageAdsState");
                Intrinsics.checkNotNullParameter(lifeCycle2, "lifeCycle");
                Intrinsics.checkNotNullParameter(lifecycleCoroutineScope2, "lifecycleCoroutineScope");
                Intrinsics.checkNotNullParameter(windowManager2, "windowManager");
                Intrinsics.checkNotNullParameter(footerBannerAdContainer, "footerBannerAdContainer");
                E.A(lifecycleCoroutineScope2, null, null, new com.quizlet.quizletandroid.ui.setpage.d(cVarQ2, lifeCycle2, windowManager2, zI ? R.string.setpage_ad_unit_AndroidTabletSetFooterFlexi : R.string.setpage_ad_unit_AndroidSetFooter320x50, setPageAdsState, footerBannerAdContainer, null), 3);
                return Unit.a;
            case 16:
                com.quizlet.features.infra.basestudy.data.models.w wVar = (com.quizlet.features.infra.basestudy.data.models.w) obj;
                boolean z2 = wVar instanceof com.quizlet.features.infra.basestudy.data.models.e;
                r activity2 = this.b;
                if (z2) {
                    activity2.P();
                    Intrinsics.checkNotNullParameter(activity2, "activity");
                    Intent intentA2 = D4.a(activity2, null);
                    intentA2.setFlags(268468224);
                    activity2.startActivity(intentA2);
                } else if (wVar instanceof com.quizlet.features.infra.basestudy.data.models.r) {
                    com.quizlet.features.infra.basestudy.data.models.r state = (com.quizlet.features.infra.basestudy.data.models.r) wVar;
                    activity2.P();
                    Intrinsics.checkNotNullParameter(activity2, "activity");
                    Intrinsics.checkNotNullParameter(state, "state");
                    String str7 = FlashcardsActivity.j;
                    Intent intentC = AbstractC3110c0.c(activity2, state);
                    intentC.setFlags(603979776);
                    activity2.startActivityForResult(intentC, 204);
                } else if (wVar instanceof t) {
                    t state2 = (t) wVar;
                    activity2.P();
                    Intrinsics.checkNotNullParameter(activity2, "activity");
                    Intrinsics.checkNotNullParameter(state2, "state");
                    String str8 = MatchActivity.s;
                    state2.getClass();
                    String str9 = state2.d;
                    webUrl = str9 != null ? str9 : "";
                    Intrinsics.checkNotNullParameter(activity2, "context");
                    StudyableModelData.StudySet studyableModelData = state2.a;
                    Intrinsics.checkNotNullParameter(studyableModelData, "studyableModelData");
                    Intrinsics.checkNotNullParameter(webUrl, "webUrl");
                    Intent intent2 = new Intent(activity2, (Class<?>) MatchActivity.class);
                    AbstractC3266t5.c(intent2, 1, studyableModelData, Long.valueOf(state2.b), state2.c, MatchActivity.s, A1.MOBILE_SCATTER.a(), null, null, 896);
                    intent2.putExtra("web_url_extra", webUrl);
                    intent2.setFlags(603979776);
                    activity2.startActivityForResult(intent2, OTUIDisplayReasonCode.UIShownCode.PC_SHOWN_SERVICE_SPECIFIC_OFF);
                } else if (wVar instanceof com.quizlet.features.infra.basestudy.data.models.s) {
                    com.quizlet.features.infra.basestudy.data.models.s state3 = (com.quizlet.features.infra.basestudy.data.models.s) wVar;
                    activity2.P();
                    Intrinsics.checkNotNullParameter(activity2, "activity");
                    Intrinsics.checkNotNullParameter(state3, "state");
                    String str10 = LearningAssistantActivity.D;
                    state3.getClass();
                    Intent intentB2 = AbstractC3675m6.b(activity2, 1, state3.a, state3.b, state3.c, state3.d, 0, state3.e, state3.f, state3.g);
                    intentB2.setFlags(603979776);
                    activity2.startActivityForResult(intentB2, OTUIDisplayReasonCode.UIShownCode.PC_SHOWN_MOVED_REGION);
                } else if (wVar instanceof com.quizlet.features.infra.basestudy.data.models.u) {
                    com.quizlet.features.infra.basestudy.data.models.u state4 = (com.quizlet.features.infra.basestudy.data.models.u) wVar;
                    activity2.P();
                    boolean zS = activity2.S();
                    Intrinsics.checkNotNullParameter(activity2, "activity");
                    Intrinsics.checkNotNullParameter(state4, "state");
                    String str11 = TestStudyModeActivity.v;
                    state4.getClass();
                    Intent intentB3 = com.quizlet.quizletandroid.ui.common.ads.prebid.creators.a.b(activity2, 1, state4.a, state4.b, state4.c, state4.d, state4.e, zS);
                    intentB3.setFlags(603979776);
                    activity2.startActivityForResult(intentB3, OTUIDisplayReasonCode.UIShownCode.PC_SHOWN_SYNC_FAILED);
                } else if (wVar instanceof com.quizlet.features.infra.basestudy.data.models.q) {
                    com.quizlet.features.infra.basestudy.data.models.q state5 = (com.quizlet.features.infra.basestudy.data.models.q) wVar;
                    activity2.P();
                    androidx.activity.result.b resultLauncher = activity2.Z;
                    if (resultLauncher == null) {
                        Intrinsics.m("gamesResultLauncher");
                        throw null;
                    }
                    Intrinsics.checkNotNullParameter(activity2, "activity");
                    Intrinsics.checkNotNullParameter(state5, "state");
                    Intrinsics.checkNotNullParameter(resultLauncher, "resultLauncher");
                    String str12 = GamesActivity.l;
                    String url = state5.a;
                    Intrinsics.checkNotNullParameter(activity2, "context");
                    Intrinsics.checkNotNullParameter(url, "url");
                    Intent intent3 = new Intent(activity2, (Class<?>) GamesActivity.class);
                    intent3.putExtra("url_extra", url);
                    resultLauncher.a(intent3);
                } else if (wVar instanceof com.quizlet.features.infra.basestudy.data.models.p) {
                    com.quizlet.features.infra.basestudy.data.models.p state6 = (com.quizlet.features.infra.basestudy.data.models.p) wVar;
                    activity2.P();
                    androidx.activity.result.b resultLauncher2 = activity2.Z;
                    if (resultLauncher2 == null) {
                        Intrinsics.m("gamesResultLauncher");
                        throw null;
                    }
                    Intrinsics.checkNotNullParameter(activity2, "activity");
                    Intrinsics.checkNotNullParameter(state6, "state");
                    Intrinsics.checkNotNullParameter(resultLauncher2, "resultLauncher");
                    String str13 = GamesActivity.l;
                    String url2 = state6.a;
                    Intrinsics.checkNotNullParameter(activity2, "context");
                    Intrinsics.checkNotNullParameter(url2, "url");
                    Intent intent4 = new Intent(activity2, (Class<?>) GamesActivity.class);
                    intent4.putExtra("url_extra", url2);
                    resultLauncher2.a(intent4);
                } else if (wVar instanceof com.quizlet.features.infra.basestudy.data.models.d) {
                    ((com.quizlet.quizletandroid.ui.setpage.navigation.a) activity2.P()).a(activity2, ((com.quizlet.features.infra.basestudy.data.models.d) wVar).a, activity2.getIntent().getBooleanExtra("isFromHome", false), activity2.S());
                } else if (wVar instanceof com.quizlet.features.infra.basestudy.data.models.c) {
                    long j = ((com.quizlet.features.infra.basestudy.data.models.c) wVar).a;
                    boolean booleanExtra = activity2.getIntent().getBooleanExtra("isFromHome", false);
                    com.quizlet.features.setpage.navigation.b bVarP = activity2.P();
                    boolean zS2 = activity2.S();
                    Intrinsics.checkNotNullParameter(activity2, "activity");
                    ((com.quizlet.quizletandroid.ui.setpage.navigation.a) bVarP).a(activity2, j, booleanExtra, zS2);
                    activity2.finish();
                } else if (wVar instanceof com.quizlet.features.infra.basestudy.data.models.a) {
                    List setIds = ((com.quizlet.features.infra.basestudy.data.models.a) wVar).a;
                    activity2.P();
                    Intrinsics.checkNotNullParameter(activity2, "activity");
                    Intrinsics.checkNotNullParameter(setIds, "setIds");
                    String str14 = AddSetToClassActivity.s;
                    activity2.startActivityForResult(S5.b(activity2, setIds), 216);
                } else if (wVar instanceof com.quizlet.features.infra.basestudy.data.models.i) {
                    activity2.P();
                    long jD2 = activity2.R().D();
                    Intrinsics.checkNotNullParameter(activity2, "context");
                    com.quizlet.quizletandroid.ui.common.adapter.c.h(1, jD2, activity2);
                } else if (wVar instanceof com.quizlet.features.infra.basestudy.data.models.b) {
                    long j2 = ((com.quizlet.features.infra.basestudy.data.models.b) wVar).a;
                    boolean booleanExtra2 = activity2.getIntent().getBooleanExtra("isFromHome", false);
                    activity2.P();
                    Intrinsics.checkNotNullParameter(activity2, "activity");
                    int i3 = com.quizlet.quizletandroid.ui.setcreation.activities.d.H;
                    Intent intent5 = new Intent(activity2, (Class<?>) EditSetActivity.class);
                    intent5.putExtra("isFromHome", booleanExtra2);
                    intent5.putExtra("editSetActivityId", j2);
                    intent5.putExtra("editSetActivityIsCopySetFlow", true);
                    activity2.startActivity(intent5);
                } else if (wVar instanceof com.quizlet.features.infra.basestudy.data.models.g) {
                    activity2.finish();
                } else if (wVar instanceof com.quizlet.features.infra.basestudy.data.models.h) {
                    long j3 = ((com.quizlet.features.infra.basestudy.data.models.h) wVar).a;
                    activity2.P();
                    Intrinsics.checkNotNullParameter(activity2, "context");
                    com.quizlet.quizletandroid.ui.profile.b bVar3 = ProfileActivity.p;
                    Intrinsics.checkNotNullParameter(activity2, "context");
                    activity2.startActivity(com.quizlet.quizletandroid.ui.profile.b.i(bVar3, activity2, j3, -1));
                } else if (wVar instanceof com.quizlet.features.infra.basestudy.data.models.n) {
                    com.quizlet.quizletandroid.ui.common.ads.prebid.creators.c cVar3 = activity2.C;
                    if (cVar3 == null) {
                        Intrinsics.m("modalNavigator");
                        throw null;
                    }
                    AbstractC1136h0 supportFragmentManager3 = activity2.getSupportFragmentManager();
                    Intrinsics.checkNotNullExpressionValue(supportFragmentManager3, "getSupportFragmentManager(...)");
                    Intrinsics.checkNotNullParameter(supportFragmentManager3, "supportFragmentManager");
                    if (supportFragmentManager3.E("expertSolutionsTag") == null) {
                        com.quizlet.upgrade.upsell.data.a type = com.quizlet.upgrade.upsell.data.a.d;
                        com.quizlet.features.infra.models.upgrade.a navigationSource = com.quizlet.features.infra.models.upgrade.a.o;
                        Intrinsics.checkNotNullParameter(type, "type");
                        Intrinsics.checkNotNullParameter("explanations_upsell", "source");
                        Intrinsics.checkNotNullParameter(navigationSource, "navigationSource");
                        UpsellModalFragment upsellModalFragment = new UpsellModalFragment();
                        upsellModalFragment.setArguments(AbstractC3206m6.a(new Pair(DBUserFields.Names.USER_UPGRADE_TYPE, type), new Pair("source", "explanations_upsell"), new Pair("navigationSource", navigationSource)));
                        upsellModalFragment.K = new com.quizlet.login.common.interactors.d((J) cVar3.b, 8);
                        upsellModalFragment.O(supportFragmentManager3, "expertSolutionsTag");
                    }
                } else if (wVar instanceof com.quizlet.features.infra.basestudy.data.models.o) {
                    com.quizlet.features.infra.basestudy.data.models.o oVar2 = (com.quizlet.features.infra.basestudy.data.models.o) wVar;
                    Intent redirectIntent = e.b(SetPageActivity.h1, activity2, oVar2.a, oVar2.b, null, null, null, false, null, 248);
                    if (activity2.C == null) {
                        Intrinsics.m("modalNavigator");
                        throw null;
                    }
                    AbstractC1136h0 supportFragmentManager4 = activity2.getSupportFragmentManager();
                    Intrinsics.checkNotNullExpressionValue(supportFragmentManager4, "getSupportFragmentManager(...)");
                    Intrinsics.checkNotNullParameter(supportFragmentManager4, "supportFragmentManager");
                    Intrinsics.checkNotNullParameter(redirectIntent, "redirectIntent");
                    SignUpWallModalFragment signUpWallModalFragment = new SignUpWallModalFragment();
                    signUpWallModalFragment.setArguments(AbstractC3206m6.a(new Pair("redirectIntent", redirectIntent)));
                    signUpWallModalFragment.O(supportFragmentManager4, SignUpWallModalFragment.X);
                } else if (wVar instanceof com.quizlet.features.infra.basestudy.data.models.m) {
                    com.quizlet.inapp.model.a reviewInfo = ((com.quizlet.features.infra.basestudy.data.models.m) wVar).a;
                    com.quizlet.inapp.manager.a aVar5 = activity2.R().C;
                    aVar5.getClass();
                    Intrinsics.checkNotNullParameter(activity2, "activity");
                    Intrinsics.checkNotNullParameter(reviewInfo, "reviewInfo");
                    com.quizlet.data.repository.searchexplanations.c cVar4 = aVar5.a;
                    Context context2 = (Context) cVar4.c;
                    Intrinsics.checkNotNullParameter(context2, "context");
                    PackageManager packageManager2 = context2.getPackageManager();
                    String str15 = (Build.VERSION.SDK_INT >= 33 ? packageManager2.getPackageInfo(context2.getPackageName(), PackageManager.PackageInfoFlags.of(128L)) : packageManager2.getPackageInfo(context2.getPackageName(), 128)).versionName;
                    if (str15 != null && (str2 = (String) StringsKt__StringsKt.split$default(str15, new String[]{"."}, false, 0, 6, null).get(1)) != null) {
                        webUrl = str2;
                    }
                    ((SharedPreferences) cVar4.b).edit().putString("APP_VERSION_KEY", webUrl).apply();
                    aVar5.b.a(activity2, reviewInfo.a);
                } else if (wVar instanceof v) {
                    activity2.P();
                    com.quizlet.features.infra.models.upgrade.a upgradeNavigationSource = com.quizlet.features.infra.models.upgrade.a.g;
                    Intrinsics.checkNotNullParameter(activity2, "activity");
                    String source = r.c1;
                    Intrinsics.checkNotNullParameter(source, "source");
                    Intrinsics.checkNotNullParameter(upgradeNavigationSource, "upgradeNavigationSource");
                    String str16 = UpgradeActivity.v;
                    activity2.startActivity(AbstractC3242q6.i(activity2, source, upgradeNavigationSource));
                } else {
                    if (!(wVar instanceof com.quizlet.features.infra.basestudy.data.models.f)) {
                        throw new NoWhenBranchMatchedException();
                    }
                    if (activity2.F == null) {
                        Intrinsics.m("devToolsManager");
                        throw null;
                    }
                }
                return Unit.a;
            case 17:
                com.quizlet.features.setpage.screenstates.h hVar = (com.quizlet.features.setpage.screenstates.h) obj;
                if (hVar instanceof com.quizlet.features.setpage.screenstates.g) {
                    com.quizlet.features.setpage.screenstates.g gVar4 = (com.quizlet.features.setpage.screenstates.g) hVar;
                    activity.W(gVar4.a, gVar4.b, true);
                } else if (hVar instanceof C4426f) {
                    C4426f c4426f = (C4426f) hVar;
                    activity.W(c4426f.a, c4426f.b, false);
                } else if (hVar instanceof C4422b) {
                    com.quizlet.uicommon.ui.common.dialogs.l.P(R.string.add_set_under_13_title_dialog, R.string.add_set_under_13_msg_dialog, R.string.got_it).O(activity.getSupportFragmentManager(), "l");
                } else if (hVar instanceof C4423c) {
                    int i4 = ((C4423c) hVar).a;
                    e.a aVar6 = new e.a(activity);
                    aVar6.i = aVar6.a.getString(R.string.OK);
                    aVar6.j = null;
                    aVar6.c(i4);
                    aVar6.g();
                } else if (hVar instanceof C4424d) {
                    C4424d c4424d = (C4424d) hVar;
                    com.quizlet.qutils.string.f fVar = c4424d.a;
                    e.a aVar7 = new e.a(activity);
                    final boolean z3 = c4424d.b;
                    aVar7.c = new DialogInterface.OnCancelListener() { // from class: com.quizlet.features.setpage.k
                        @Override // android.content.DialogInterface.OnCancelListener
                        public final void onCancel(DialogInterface dialogInterface) {
                            dialogInterface.dismiss();
                            if (z3) {
                                activity.finish();
                            }
                        }
                    };
                    aVar7.e(R.string.OK, new com.google.firebase.messaging.s(z3, activity));
                    aVar7.e = AbstractC3053s1.e(fVar, activity);
                    aVar7.g();
                } else if (Intrinsics.b(hVar, C4425e.a)) {
                    Intrinsics.checkNotNullParameter(activity, "context");
                    String message2 = activity.getString(R.string.set_page_feature_offline_blocked_description);
                    Intrinsics.checkNotNullExpressionValue(message2, "getString(...)");
                    Intrinsics.checkNotNullParameter(message2, "message");
                    String title = activity.getString(R.string.set_page_feature_offline_blocked_title);
                    Intrinsics.checkNotNullExpressionValue(title, "getString(...)");
                    Intrinsics.checkNotNullParameter(title, "title");
                    String text = activity.getString(R.string.got_it);
                    Intrinsics.checkNotNullExpressionValue(text, "getString(...)");
                    Intrinsics.checkNotNullParameter(text, "text");
                    com.quizlet.uicommon.ui.common.dialogs.i iVar2 = new com.quizlet.uicommon.ui.common.dialogs.i(new QAlertDialogFragment.DialogData(message2, title, text, null, true, null), null, null, null);
                    String str17 = QAlertDialogFragment.t;
                    com.quizlet.uicommon.ui.common.dialogs.h.a(iVar2).O(activity.getSupportFragmentManager(), QAlertDialogFragment.t);
                } else {
                    if (!Intrinsics.b(hVar, C4421a.a)) {
                        throw new NoWhenBranchMatchedException();
                    }
                    String title2 = activity.getString(R.string.set_remove_from_downloaded_confirmation_title);
                    Intrinsics.checkNotNullExpressionValue(title2, "getString(...)");
                    String description = activity.getString(R.string.set_remove_from_downloaded_confirmation_message);
                    Intrinsics.checkNotNullExpressionValue(description, "getString(...)");
                    String actionText = activity.getString(R.string.set_remove_from_downloaded_confirmation_button);
                    Intrinsics.checkNotNullExpressionValue(actionText, "getString(...)");
                    String cancelText = activity.getString(R.string.cancel);
                    Intrinsics.checkNotNullExpressionValue(cancelText, "getString(...)");
                    Intrinsics.checkNotNullParameter(title2, "title");
                    Intrinsics.checkNotNullParameter(description, "description");
                    Intrinsics.checkNotNullParameter(actionText, "actionText");
                    Intrinsics.checkNotNullParameter(cancelText, "cancelText");
                    ConfirmationModalFragment confirmationModalFragment = new ConfirmationModalFragment();
                    Bundle bundle3 = new Bundle();
                    bundle3.putString("ARG_TITLE", title2);
                    bundle3.putString("ARG_DESCRIPTION", description);
                    bundle3.putString("ARG_ACTION_TEXT", actionText);
                    bundle3.putString("ARG_CANCEL_TEXT", cancelText);
                    confirmationModalFragment.setArguments(bundle3);
                    confirmationModalFragment.F = new i(activity, 11);
                    confirmationModalFragment.O(activity.getSupportFragmentManager(), "ConfirmationModalFragment");
                }
                return Unit.a;
            default:
                com.quizlet.features.setpage.screenstates.E e = (com.quizlet.features.setpage.screenstates.E) obj;
                boolean z4 = e instanceof com.quizlet.features.setpage.screenstates.B;
                final r rVar3 = this.b;
                if (z4) {
                    DBStudySet dBStudySet2 = ((com.quizlet.features.setpage.screenstates.B) e).a;
                    i iVar3 = new i(rVar3, 12);
                    com.quizlet.features.setpage.utils.setpermissions.a aVar8 = rVar3.x;
                    if (aVar8 == null) {
                        Intrinsics.m("permissionsViewUtil");
                        throw null;
                    }
                    io.reactivex.rxjava3.internal.operators.completable.a aVarB2 = ((com.quizlet.features.setpage.utils.setpermissions.f) aVar8).b(dBStudySet2, rVar3, false, R.string.no_password_view_exception, R.string.set_permission_error, new g(rVar3, 13), new com.google.firebase.crashlytics.internal.metadata.q(iVar3, 10));
                    io.reactivex.rxjava3.functions.d dVar2 = new io.reactivex.rxjava3.functions.d() { // from class: com.quizlet.features.setpage.l
                        @Override // io.reactivex.rxjava3.functions.d
                        public final void accept(Object obj2) {
                            switch (i2) {
                                case 0:
                                    io.reactivex.rxjava3.disposables.b disposable = (io.reactivex.rxjava3.disposables.b) obj2;
                                    Intrinsics.checkNotNullParameter(disposable, "p0");
                                    com.quizlet.quizletandroid.ui.base.g gVar22 = rVar3.e;
                                    gVar22.getClass();
                                    Intrinsics.checkNotNullParameter(disposable, "disposable");
                                    com.quizlet.baseui.managers.b bVar4 = gVar22.c;
                                    Intrinsics.checkNotNullParameter(disposable, "disposable");
                                    Object value22 = bVar4.b.getValue();
                                    Intrinsics.checkNotNullExpressionValue(value22, "getValue(...)");
                                    ((io.reactivex.rxjava3.disposables.a) value22).b(disposable);
                                    break;
                                default:
                                    io.reactivex.rxjava3.disposables.b p0 = (io.reactivex.rxjava3.disposables.b) obj2;
                                    Intrinsics.checkNotNullParameter(p0, "p0");
                                    rVar3.y(p0);
                                    break;
                            }
                        }
                    };
                    com.quizlet.infra.legacysyncengine.net.request.g gVar5 = io.reactivex.rxjava3.internal.functions.d.d;
                    io.reactivex.rxjava3.internal.functions.b bVar4 = io.reactivex.rxjava3.internal.functions.d.c;
                    new io.reactivex.rxjava3.internal.operators.completable.i(aVarB2, dVar2, gVar5, bVar4, bVar4).e();
                } else if (e instanceof D) {
                    e.a aVar9 = new e.a(rVar3);
                    aVar9.c(R.string.set_permission_error);
                    aVar9.b = false;
                    aVar9.e(R.string.got_it, new j(rVar3, i));
                    aVar9.g();
                } else if (!Intrinsics.b(e, c)) {
                    throw new NoWhenBranchMatchedException();
                }
                return Unit.a;
        }
    }
}

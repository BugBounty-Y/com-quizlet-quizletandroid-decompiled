package com.quizlet.features.setpage;

import android.animation.ValueAnimator;
import android.content.Context;
import android.content.Intent;
import android.content.res.Resources;
import android.os.Bundle;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.FrameLayout;
import android.widget.ProgressBar;
import android.widget.RelativeLayout;
import androidx.activity.v;
import androidx.camera.camera2.internal.C0138o;
import androidx.compose.ui.node.B;
import androidx.compose.ui.platform.ComposeView;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.coordinatorlayout.widget.CoordinatorLayout;
import androidx.core.view.L;
import androidx.core.view.V;
import androidx.fragment.app.AbstractC1136h0;
import androidx.fragment.app.C1121a;
import androidx.fragment.app.Fragment;
import androidx.lifecycle.Z;
import androidx.lifecycle.p0;
import com.facebook.login.E;
import com.google.android.gms.internal.mlkit_vision_barcode.B7;
import com.google.android.gms.internal.mlkit_vision_barcode.I6;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.google.android.material.appbar.AppBarLayout;
import com.google.android.material.appbar.CollapsingToolbarLayout;
import com.onetrust.otpublishers.headless.Public.OTUIDisplayReason.OTUIDisplayReasonCode;
import com.quizlet.data.model.Z1;
import com.quizlet.db.data.models.persisted.DBSession;
import com.quizlet.db.data.models.persisted.DBStudySet;
import com.quizlet.db.data.models.persisted.base.ModelType;
import com.quizlet.db.data.models.persisted.base.Models;
import com.quizlet.eventlogger.features.study.StudyFunnelEventLogger;
import com.quizlet.features.achievements.achievement.AchievementEarnedView;
import com.quizlet.features.setpage.header.ui.SetPageHeaderFragment;
import com.quizlet.features.setpage.studypreview.StudyPreviewFragment;
import com.quizlet.features.setpage.terms.ui.SelectedTermsModeFragment;
import com.quizlet.features.setpage.viewmodel.C4428b;
import com.quizlet.features.setpage.viewmodel.C4429c;
import com.quizlet.features.setpage.viewmodel.C4433g;
import com.quizlet.features.setpage.viewmodel.C4435i;
import com.quizlet.features.setpage.viewmodel.F;
import com.quizlet.features.setpage.viewmodel.P;
import com.quizlet.generated.enums.EnumC4519s1;
import com.quizlet.generated.enums.EnumC4525u1;
import com.quizlet.generated.enums.G1;
import com.quizlet.partskit.widgets.QButton;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.y;
import com.quizlet.qutils.string.f;
import com.quizlet.uicommon.ui.common.views.SimpleGradientView;
import io.reactivex.rxjava3.internal.operators.observable.C;
import io.reactivex.rxjava3.subjects.d;
import java.util.UUID;
import java.util.WeakHashMap;
import kotlin.Unit;
import kotlin.collections.C4933y;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;
import kotlin.u;

/* loaded from: classes3.dex */
public abstract class r extends com.quizlet.baseui.base.f implements com.quizlet.features.setpage.termlist.contracts.b {
    public static final String c1;
    public com.google.firebase.crashlytics.b A;
    public com.quizlet.shared.usecase.folderstudymaterials.b B;
    public com.quizlet.quizletandroid.ui.common.ads.prebid.creators.c C;
    public com.quizlet.quizletandroid.ui.setpage.navigation.a D;
    public com.quizlet.data.interactor.set.c E;
    public com.quizlet.quizletandroid.ui.debug.a F;
    public boolean M;
    public ValueAnimator V;
    public com.quizlet.uicommon.ui.common.dialogs.k W;
    public int X;
    public int Y;
    public androidx.activity.result.b Z;
    public com.quizlet.quizletandroid.managers.c w;
    public com.quizlet.features.setpage.utils.setpermissions.a x;
    public com.quizlet.quizletandroid.util.a y;
    public com.quizlet.data.repository.user.a z;
    public final u l = kotlin.l.b(new i(this, 0));
    public final u m = kotlin.l.b(new i(this, 2));
    public final u n = kotlin.l.b(new i(this, 3));
    public final u o = kotlin.l.b(new i(this, 4));
    public final u p = kotlin.l.b(new i(this, 5));
    public final u q = kotlin.l.b(new i(this, 6));
    public final u r = kotlin.l.b(new i(this, 7));
    public final u s = kotlin.l.b(new i(this, 8));
    public final u t = kotlin.l.b(new i(this, 9));
    public final u u = kotlin.l.b(new i(this, 10));
    public final u v = kotlin.l.b(new i(this, 1));
    public final com.quizlet.data.repository.folderwithcreatorinclass.e G = new com.quizlet.data.repository.folderwithcreatorinclass.e(K.a(P.class), new p(this, 10), new p(this, 9), new p(this, 11));
    public final com.quizlet.data.repository.folderwithcreatorinclass.e H = new com.quizlet.data.repository.folderwithcreatorinclass.e(K.a(com.quizlet.features.setpage.progress.presentation.viewmodel.a.class), new p(this, 13), new p(this, 12), new p(this, 14));
    public final com.quizlet.data.repository.folderwithcreatorinclass.e I = new com.quizlet.data.repository.folderwithcreatorinclass.e(K.a(com.quizlet.features.achievements.notification.f.class), new p(this, 16), new p(this, 15), new p(this, 17));
    public final com.quizlet.data.repository.folderwithcreatorinclass.e J = new com.quizlet.data.repository.folderwithcreatorinclass.e(K.a(com.quizlet.uicommon.ui.common.overflowmenu.i.class), new p(this, 1), new p(this, 0), new p(this, 2));
    public final com.quizlet.data.repository.folderwithcreatorinclass.e K = new com.quizlet.data.repository.folderwithcreatorinclass.e(K.a(com.quizlet.features.setpage.studypreview.g.class), new p(this, 4), new p(this, 3), new p(this, 5));
    public final com.quizlet.data.repository.folderwithcreatorinclass.e L = new com.quizlet.data.repository.folderwithcreatorinclass.e(K.a(com.quizlet.features.setpage.termlist.viewmodel.j.class), new p(this, 7), new p(this, 6), new p(this, 8));

    static {
        Intrinsics.checkNotNullExpressionValue("SetPageActivity", "getSimpleName(...)");
        c1 = "SetPageActivity";
    }

    @Override // com.quizlet.baseui.base.b
    public final String D() {
        return c1;
    }

    @Override // com.quizlet.baseui.base.b
    public final boolean H() {
        return false;
    }

    @Override // com.quizlet.baseui.base.f
    public final androidx.viewbinding.a N() {
        View viewInflate = getLayoutInflater().inflate(R.layout.activity_setpage, (ViewGroup) null, false);
        int i = R.id.achievementToast;
        AchievementEarnedView achievementEarnedView = (AchievementEarnedView) AbstractC3375o2.c(R.id.achievementToast, viewInflate);
        if (achievementEarnedView != null) {
            i = R.id.bottom_fading_edge;
            SimpleGradientView simpleGradientView = (SimpleGradientView) AbstractC3375o2.c(R.id.bottom_fading_edge, viewInflate);
            if (simpleGradientView != null) {
                i = R.id.layout_collapsing_appbar;
                AppBarLayout appBarLayout = (AppBarLayout) AbstractC3375o2.c(R.id.layout_collapsing_appbar, viewInflate);
                if (appBarLayout != null) {
                    i = R.id.layout_collapsing_appbar_toolbar;
                    if (((CollapsingToolbarLayout) AbstractC3375o2.c(R.id.layout_collapsing_appbar_toolbar, viewInflate)) != null) {
                        ConstraintLayout constraintLayout = (ConstraintLayout) viewInflate;
                        i = R.id.set_progress_fragment_container;
                        FrameLayout frameLayout = (FrameLayout) AbstractC3375o2.c(R.id.set_progress_fragment_container, viewInflate);
                        if (frameLayout != null) {
                            i = R.id.set_selected_terms_mode_fragment_container;
                            FrameLayout frameLayout2 = (FrameLayout) AbstractC3375o2.c(R.id.set_selected_terms_mode_fragment_container, viewInflate);
                            if (frameLayout2 != null) {
                                i = R.id.setpage_footer_banner_ad;
                                FrameLayout frameLayout3 = (FrameLayout) AbstractC3375o2.c(R.id.setpage_footer_banner_ad, viewInflate);
                                if (frameLayout3 != null) {
                                    i = R.id.setpage_header_banner_ad;
                                    FrameLayout frameLayout4 = (FrameLayout) AbstractC3375o2.c(R.id.setpage_header_banner_ad, viewInflate);
                                    if (frameLayout4 != null) {
                                        i = R.id.setpage_header_container;
                                        FrameLayout frameLayout5 = (FrameLayout) AbstractC3375o2.c(R.id.setpage_header_container, viewInflate);
                                        if (frameLayout5 != null) {
                                            i = R.id.setpage_header_subscription_ad;
                                            ComposeView composeView = (ComposeView) AbstractC3375o2.c(R.id.setpage_header_subscription_ad, viewInflate);
                                            if (composeView != null) {
                                                i = R.id.setpage_loading_spinner;
                                                ProgressBar progressBar = (ProgressBar) AbstractC3375o2.c(R.id.setpage_loading_spinner, viewInflate);
                                                if (progressBar != null) {
                                                    i = R.id.setpage_loading_spinner_container;
                                                    if (((RelativeLayout) AbstractC3375o2.c(R.id.setpage_loading_spinner_container, viewInflate)) != null) {
                                                        i = R.id.setpage_study_preview_container;
                                                        FrameLayout frameLayout6 = (FrameLayout) AbstractC3375o2.c(R.id.setpage_study_preview_container, viewInflate);
                                                        if (frameLayout6 != null) {
                                                            i = R.id.setpage_study_set_button;
                                                            QButton qButton = (QButton) AbstractC3375o2.c(R.id.setpage_study_set_button, viewInflate);
                                                            if (qButton != null) {
                                                                i = R.id.setpage_study_set_button_container;
                                                                FrameLayout frameLayout7 = (FrameLayout) AbstractC3375o2.c(R.id.setpage_study_set_button_container, viewInflate);
                                                                if (frameLayout7 != null) {
                                                                    i = R.id.snackbar_anchor;
                                                                    View viewC = AbstractC3375o2.c(R.id.snackbar_anchor, viewInflate);
                                                                    if (viewC != null) {
                                                                        i = R.id.snackbar_layout_wrapper;
                                                                        CoordinatorLayout coordinatorLayout = (CoordinatorLayout) AbstractC3375o2.c(R.id.snackbar_layout_wrapper, viewInflate);
                                                                        if (coordinatorLayout != null) {
                                                                            i = R.id.term_list_fragment_container;
                                                                            FrameLayout frameLayout8 = (FrameLayout) AbstractC3375o2.c(R.id.term_list_fragment_container, viewInflate);
                                                                            if (frameLayout8 != null) {
                                                                                i = R.id.toolbar;
                                                                                ComposeView composeView2 = (ComposeView) AbstractC3375o2.c(R.id.toolbar, viewInflate);
                                                                                if (composeView2 != null) {
                                                                                    com.quizlet.features.setpage.databinding.a aVar = new com.quizlet.features.setpage.databinding.a(constraintLayout, achievementEarnedView, simpleGradientView, appBarLayout, frameLayout, frameLayout2, frameLayout3, frameLayout4, frameLayout5, composeView, progressBar, frameLayout6, qButton, frameLayout7, viewC, coordinatorLayout, frameLayout8, composeView2);
                                                                                    Intrinsics.checkNotNullExpressionValue(aVar, "inflate(...)");
                                                                                    return aVar;
                                                                                }
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(viewInflate.getResources().getResourceName(i)));
    }

    public final ViewGroup O() {
        Object value = this.q.getValue();
        Intrinsics.checkNotNullExpressionValue(value, "getValue(...)");
        return (ViewGroup) value;
    }

    public final com.quizlet.features.setpage.navigation.b P() {
        com.quizlet.quizletandroid.ui.setpage.navigation.a aVar = this.D;
        if (aVar != null) {
            return aVar;
        }
        Intrinsics.m("setPageNavigator");
        throw null;
    }

    public final com.quizlet.data.interactor.set.c Q() {
        com.quizlet.data.interactor.set.c cVar = this.E;
        if (cVar != null) {
            return cVar;
        }
        Intrinsics.m("setPageViewDisplayer");
        throw null;
    }

    public final P R() {
        return (P) this.G.getValue();
    }

    public final boolean S() {
        return getIntent().getBooleanExtra("shouldDismissAfterStudyModeFinished", false);
    }

    public final View T() {
        Object value = this.o.getValue();
        Intrinsics.checkNotNullExpressionValue(value, "getValue(...)");
        return (View) value;
    }

    public final void U(boolean z) {
        Object value = this.s.getValue();
        Intrinsics.checkNotNullExpressionValue(value, "getValue(...)");
        ((View) value).setVisibility(z ? 0 : 8);
        Object value2 = this.r.getValue();
        Intrinsics.checkNotNullExpressionValue(value2, "getValue(...)");
        ((View) value2).setVisibility(z ? 8 : 0);
    }

    public final void V(boolean z) {
        if (!z) {
            com.quizlet.uicommon.ui.common.dialogs.k kVar = this.W;
            if (kVar != null) {
                kVar.dismiss();
            }
            this.W = null;
            return;
        }
        if (this.W == null) {
            com.quizlet.uicommon.ui.common.dialogs.k kVar2 = new com.quizlet.uicommon.ui.common.dialogs.k(this, getString(R.string.syncing_set_progress));
            kVar2.setCancelable(false);
            this.W = kVar2;
        }
        G(this.W);
    }

    public final void W(DBStudySet set, com.quizlet.features.infra.basestudy.data.models.shareset.a shareStatus, boolean z) {
        if (this.C == null) {
            Intrinsics.m("modalNavigator");
            throw null;
        }
        AbstractC1136h0 supportFragmentManager = getSupportFragmentManager();
        Intrinsics.checkNotNullExpressionValue(supportFragmentManager, "getSupportFragmentManager(...)");
        com.braze.push.g onShowDialog = new com.braze.push.g(z, 2, this);
        Intrinsics.checkNotNullParameter(supportFragmentManager, "supportFragmentManager");
        Intrinsics.checkNotNullParameter(set, "set");
        Intrinsics.checkNotNullParameter(shareStatus, "shareStatus");
        Intrinsics.checkNotNullParameter(onShowDialog, "onShowDialog");
        long setId = set.getSetId();
        String webUrl = set.getWebUrl();
        String studySetTitle = set.getTitle();
        String str = com.quizlet.quizletandroid.ui.setpage.shareset.c.I;
        Fragment fragmentE = supportFragmentManager.E(str);
        if ((fragmentE instanceof com.quizlet.quizletandroid.ui.setpage.shareset.c ? (com.quizlet.quizletandroid.ui.setpage.shareset.c) fragmentE : null) != null || studySetTitle == null) {
            return;
        }
        Intrinsics.checkNotNullParameter(shareStatus, "shareStatus");
        Intrinsics.checkNotNullParameter(studySetTitle, "studySetTitle");
        com.quizlet.quizletandroid.ui.setpage.shareset.c cVar = new com.quizlet.quizletandroid.ui.setpage.shareset.c();
        Bundle bundle = new Bundle();
        bundle.putLong("argStudySetId", setId);
        bundle.putString("argStudySetTitle", studySetTitle);
        bundle.putString("argStudySetWebUrl", webUrl);
        bundle.putString("argShareStatus", shareStatus.toString());
        bundle.putBoolean("argDisplayWhatsappShare", z);
        cVar.setArguments(bundle);
        cVar.O(supportFragmentManager, str);
        onShowDialog.invoke();
    }

    @Override // com.quizlet.baseui.base.b, androidx.fragment.app.I, androidx.activity.s, android.app.Activity
    public final void onActivityResult(int i, int i2, Intent intent) throws Exception {
        super.onActivityResult(i, i2, intent);
        if (i != 201) {
            if (i != 209) {
                if (i != 216) {
                    if (i != 230) {
                        switch (i) {
                            case 204:
                                if (!S()) {
                                    R().Y.j(Unit.a);
                                    break;
                                } else {
                                    finish();
                                    break;
                                }
                            case 205:
                            case OTUIDisplayReasonCode.UIShownCode.PC_SHOWN_SERVICE_SPECIFIC_OFF /* 206 */:
                            case OTUIDisplayReasonCode.UIShownCode.PC_SHOWN_SYNC_FAILED /* 207 */:
                                if (!S()) {
                                    R().Y.j(Unit.a);
                                    break;
                                } else {
                                    finish();
                                    break;
                                }
                        }
                    } else if (S()) {
                        finish();
                    } else {
                        Unit unit = Unit.a;
                    }
                } else if (i2 == -1) {
                    com.quizlet.quizletandroid.util.a aVar = this.y;
                    if (aVar == null) {
                        Intrinsics.m("addSetToClassManager");
                        throw null;
                    }
                    Intrinsics.d(intent);
                    Intrinsics.checkNotNullParameter(this, "activity");
                    Intrinsics.checkNotNullParameter(this, "snackbarAnchorProvider");
                    Intrinsics.checkNotNullParameter(intent, "intent");
                    aVar.a(this, intent, new androidx.lifecycle.compose.d(aVar, this, this, 25));
                }
            } else if (i2 != 106) {
                if (i2 == 114) {
                    P pR = R();
                    pR.getClass();
                    pR.I(new C4428b(pR, 3), new F(pR, null));
                } else if (i2 != 115) {
                    if (S()) {
                        finish();
                    } else {
                        Unit unit2 = Unit.a;
                    }
                } else if (S()) {
                    finish();
                } else {
                    R().Y.j(Unit.a);
                }
            } else if (S()) {
                finish();
            } else {
                I6.e((CoordinatorLayout) this.t.getValue(), getString(R.string.learning_assistant_error)).i();
                Unit unit3 = Unit.a;
            }
        } else if (i2 == 100) {
            finish();
        } else if (S()) {
            setResult(-1);
            finish();
        }
        P pR2 = R();
        pR2.getClass();
        ModelType<DBSession> modelType = Models.SESSION;
        com.quizlet.infra.legacysyncengine.net.f fVar = pR2.j;
        fVar.c(modelType);
        fVar.c(Models.ANSWER);
        fVar.c(Models.QUESTION_ATTRIBUTE);
    }

    @Override // com.quizlet.baseui.base.f, com.quizlet.baseui.base.b, androidx.fragment.app.I, androidx.activity.s, androidx.core.app.AbstractActivityC1021h, android.app.Activity
    public void onCreate(Bundle bundle) {
        int i = 18;
        int i2 = 5;
        int i3 = 0;
        final int i4 = 1;
        int i5 = 6;
        super.onCreate(bundle);
        int i6 = 3;
        v.b(this, null, 3);
        kotlin.jvm.internal.F f = new kotlin.jvm.internal.F();
        f.a = true;
        com.quizlet.features.setpage.databinding.a aVar = (com.quizlet.features.setpage.databinding.a) K();
        com.google.firebase.tracing.a aVar2 = new com.google.firebase.tracing.a(11, this, f);
        WeakHashMap weakHashMap = V.a;
        L.m(aVar.a, aVar2);
        if (R().D() == 0) {
            finish();
            return;
        }
        com.google.firebase.crashlytics.b bVar = this.A;
        if (bVar == null) {
            Intrinsics.m("firebaseCrashlytics");
            throw null;
        }
        long jD = R().D();
        com.google.firebase.crashlytics.internal.common.q qVar = bVar.a;
        qVar.o.a.a(new E(qVar, "last_set_viewed", Long.toString(jD), i4));
        getSupportFragmentManager().b(new com.quizlet.explanations.textbook.ui.b(this, i4));
        getSupportFragmentManager().h0("upsellRequestKey", this, new j(this, i3));
        if (this.B == null) {
            Intrinsics.m("setPageComposeDelegator");
            throw null;
        }
        ComposeView composeView = ((com.quizlet.features.setpage.databinding.a) K()).r;
        Intrinsics.checkNotNullExpressionValue(composeView, "toolbar");
        P viewModel = R();
        com.quizlet.features.notes.paywall.a onNavigateUp = new com.quizlet.features.notes.paywall.a(0, this, com.quizlet.features.setpage.utils.activities.a.class, "navigateUp", "navigateUp(Landroid/app/Activity;)V", 1, 23);
        Intrinsics.checkNotNullParameter(composeView, "composeView");
        Intrinsics.checkNotNullParameter(viewModel, "viewModel");
        Intrinsics.checkNotNullParameter(onNavigateUp, "onNavigateUp");
        composeView.setContent(new androidx.compose.runtime.internal.d(true, 1216128628, new com.quizlet.features.practicetest.results.i(i2, onNavigateUp, viewModel)));
        R().d1.f(this, new com.quizlet.explanations.feedback.ui.fragments.c(6, new g(this, 7)));
        R().e1.f(this, new com.quizlet.explanations.feedback.ui.fragments.c(6, new g(this, 8)));
        R().j1.f(this, new com.quizlet.explanations.feedback.ui.fragments.c(6, new g(this, 17)));
        R().f1.f(this, new com.quizlet.explanations.feedback.ui.fragments.c(6, new g(this, i2)));
        R().g1.f(this, new com.quizlet.explanations.feedback.ui.fragments.c(6, new g(this, i5)));
        kotlinx.coroutines.E.A(p0.h(this), null, null, new o(this, null), 3);
        R().i1.f(this, new com.quizlet.explanations.feedback.ui.fragments.c(6, new g(this, 16)));
        R().Z.f(this, new com.quizlet.explanations.feedback.ui.fragments.c(6, new g(this, 9)));
        R().c1.f(this, new com.quizlet.explanations.feedback.ui.fragments.c(6, new g(this, 10)));
        R().k1.f(this, new com.quizlet.explanations.feedback.ui.fragments.c(6, new g(this, i)));
        R().X.f(this, new com.quizlet.explanations.feedback.ui.fragments.c(6, new g(this, 12)));
        R().n1.f(this, new com.quizlet.explanations.feedback.ui.fragments.c(6, new g(this, 15)));
        R().l1.f(this, new Z(this) { // from class: com.quizlet.features.setpage.f
            public final /* synthetic */ r b;

            {
                this.b = this;
            }

            @Override // androidx.lifecycle.Z
            public final void a(Object obj) {
                switch (i4) {
                    case 0:
                        com.quizlet.features.setpage.screenstates.k kVar = (com.quizlet.features.setpage.screenstates.k) obj;
                        if (kVar != null) {
                            com.quizlet.data.repository.user.a aVar3 = this.b.z;
                            if (aVar3 == null) {
                                Intrinsics.m("gaLogger");
                                throw null;
                            }
                            aVar3.s(r.c1, kVar.a, kVar.b, G1.SET, null);
                            return;
                        }
                        return;
                    case 1:
                        if (((com.quizlet.features.setpage.screenstates.i) obj) != null) {
                            r rVar = this.b;
                            Intent intent = rVar.getIntent();
                            intent.removeExtra("studyMode");
                            intent.removeExtra("matchHighScore");
                            rVar.setIntent(intent);
                            return;
                        }
                        return;
                    default:
                        if (((com.quizlet.features.setpage.screenstates.j) obj) != null) {
                            r rVar2 = this.b;
                            Intent intent2 = rVar2.getIntent();
                            intent2.removeExtra("isNewStudySet");
                            rVar2.setIntent(intent2);
                            return;
                        }
                        return;
                }
            }
        });
        final int i7 = 2;
        R().m1.f(this, new Z(this) { // from class: com.quizlet.features.setpage.f
            public final /* synthetic */ r b;

            {
                this.b = this;
            }

            @Override // androidx.lifecycle.Z
            public final void a(Object obj) {
                switch (i7) {
                    case 0:
                        com.quizlet.features.setpage.screenstates.k kVar = (com.quizlet.features.setpage.screenstates.k) obj;
                        if (kVar != null) {
                            com.quizlet.data.repository.user.a aVar3 = this.b.z;
                            if (aVar3 == null) {
                                Intrinsics.m("gaLogger");
                                throw null;
                            }
                            aVar3.s(r.c1, kVar.a, kVar.b, G1.SET, null);
                            return;
                        }
                        return;
                    case 1:
                        if (((com.quizlet.features.setpage.screenstates.i) obj) != null) {
                            r rVar = this.b;
                            Intent intent = rVar.getIntent();
                            intent.removeExtra("studyMode");
                            intent.removeExtra("matchHighScore");
                            rVar.setIntent(intent);
                            return;
                        }
                        return;
                    default:
                        if (((com.quizlet.features.setpage.screenstates.j) obj) != null) {
                            r rVar2 = this.b;
                            Intent intent2 = rVar2.getIntent();
                            intent2.removeExtra("isNewStudySet");
                            rVar2.setIntent(intent2);
                            return;
                        }
                        return;
                }
            }
        });
        final int i8 = 0;
        R().o1.f(this, new Z(this) { // from class: com.quizlet.features.setpage.f
            public final /* synthetic */ r b;

            {
                this.b = this;
            }

            @Override // androidx.lifecycle.Z
            public final void a(Object obj) {
                switch (i8) {
                    case 0:
                        com.quizlet.features.setpage.screenstates.k kVar = (com.quizlet.features.setpage.screenstates.k) obj;
                        if (kVar != null) {
                            com.quizlet.data.repository.user.a aVar3 = this.b.z;
                            if (aVar3 == null) {
                                Intrinsics.m("gaLogger");
                                throw null;
                            }
                            aVar3.s(r.c1, kVar.a, kVar.b, G1.SET, null);
                            return;
                        }
                        return;
                    case 1:
                        if (((com.quizlet.features.setpage.screenstates.i) obj) != null) {
                            r rVar = this.b;
                            Intent intent = rVar.getIntent();
                            intent.removeExtra("studyMode");
                            intent.removeExtra("matchHighScore");
                            rVar.setIntent(intent);
                            return;
                        }
                        return;
                    default:
                        if (((com.quizlet.features.setpage.screenstates.j) obj) != null) {
                            r rVar2 = this.b;
                            Intent intent2 = rVar2.getIntent();
                            intent2.removeExtra("isNewStudySet");
                            rVar2.setIntent(intent2);
                            return;
                        }
                        return;
                }
            }
        });
        R().p1.f(this, new com.quizlet.explanations.feedback.ui.fragments.c(6, new g(this, i8)));
        R().q1.f(this, new com.quizlet.explanations.feedback.ui.fragments.c(6, new g(this, i4)));
        R().Y.f(this, new com.quizlet.explanations.feedback.ui.fragments.c(6, new g(this, 2)));
        com.quizlet.data.repository.folderwithcreatorinclass.e eVar = this.I;
        ((com.quizlet.features.achievements.notification.f) eVar.getValue()).f.f(this, new com.quizlet.explanations.feedback.ui.fragments.c(6, new g(this, i6)));
        ((com.quizlet.features.achievements.notification.f) eVar.getValue()).g.f(this, new com.quizlet.explanations.feedback.ui.fragments.c(6, new g(this, 4)));
        R().h1.f(this, new com.quizlet.explanations.feedback.ui.fragments.c(6, new g(this, 11)));
        kotlinx.coroutines.E.A(p0.h(this), null, null, new n(this, null), 3);
        Object value = this.u.getValue();
        Intrinsics.checkNotNullExpressionValue(value, "getValue(...)");
        ((Button) value).setOnClickListener(new com.braze.ui.inappmessage.d(this, 26));
        int i9 = 4;
        this.Z = registerForActivityResult(new androidx.activity.result.contract.b(i9), new androidx.activity.compose.b(this, i9));
        P pR = R();
        if (pR.B1 != pR.D()) {
            pR.B1 = pR.D();
            long jD2 = pR.D();
            com.quizlet.features.infra.basestudy.manager.d dVar = pR.w;
            UUID uuid = (UUID) dVar.b.get(String.valueOf(jD2));
            if (uuid != null) {
                StudyFunnelEventLogger.a(dVar.a, EnumC4519s1.CONTAINER_PAGE_VIEW, Long.valueOf(jD2), 1, uuid, EnumC4525u1.SET_PAGE, null, 0, 0, null, null, null, null, 3840);
            }
            io.reactivex.rxjava3.subjects.h hVar = pR.x1;
            C4435i c4435i = new C4435i(pR, i6);
            com.quizlet.billing.manager.d dVar2 = new com.quizlet.billing.manager.d(timber.log.c.a, 3);
            io.reactivex.rxjava3.internal.functions.b bVar2 = io.reactivex.rxjava3.internal.functions.d.c;
            hVar.getClass();
            io.reactivex.rxjava3.internal.operators.completable.l lVar = new io.reactivex.rxjava3.internal.operators.completable.l(c4435i, dVar2, bVar2);
            hVar.e(lVar);
            Intrinsics.checkNotNullExpressionValue(lVar, "subscribe(...)");
            Intrinsics.checkNotNullParameter(lVar, "<this>");
            pR.A(lVar);
        }
        View viewFindViewById = findViewById(R.id.setpage_study_preview_container);
        if (viewFindViewById != null) {
            viewFindViewById.setVisibility(0);
        }
        Q();
        AbstractC1136h0 fragmentManager = getSupportFragmentManager();
        Intrinsics.checkNotNullExpressionValue(fragmentManager, "getSupportFragmentManager(...)");
        Intrinsics.checkNotNullParameter(fragmentManager, "fragmentManager");
        String str = StudyPreviewFragment.k;
        if (fragmentManager.E(str) == null) {
            C1121a c1121a = new C1121a(fragmentManager);
            c1121a.l(R.id.setpage_study_preview_container, new StudyPreviewFragment(), str);
            c1121a.g();
        }
        Q();
        AbstractC1136h0 fragmentManager2 = getSupportFragmentManager();
        Intrinsics.checkNotNullExpressionValue(fragmentManager2, "getSupportFragmentManager(...)");
        Intrinsics.checkNotNullParameter(fragmentManager2, "fragmentManager");
        String str2 = SetPageHeaderFragment.m;
        Fragment fragmentE = fragmentManager2.E(str2);
        if ((fragmentE instanceof SetPageHeaderFragment ? (SetPageHeaderFragment) fragmentE : null) == null) {
            C1121a c1121a2 = new C1121a(fragmentManager2);
            c1121a2.l(R.id.setpage_header_container, new SetPageHeaderFragment(), str2);
            c1121a2.g();
        }
        AbstractC1136h0 supportFragmentManager = getSupportFragmentManager();
        String str3 = SelectedTermsModeFragment.l;
        if (supportFragmentManager.E(str3) == null) {
            AbstractC1136h0 supportFragmentManager2 = getSupportFragmentManager();
            C1121a c1121aB = B.b(supportFragmentManager2, supportFragmentManager2);
            c1121aB.l(R.id.set_selected_terms_mode_fragment_container, new SelectedTermsModeFragment(), str3);
            c1121aB.g();
        }
        P pR2 = R();
        if (pR2.A1) {
            pR2.K();
            pR2.A1 = false;
        }
        pR2.g1.l(Unit.a);
        io.reactivex.rxjava3.internal.observers.e eVarB = B7.b(pR2.v.p(pR2.d), io.reactivex.rxjava3.kotlin.c.b, new C4429c(pR2, i6));
        Intrinsics.checkNotNullParameter(eVarB, "<this>");
        pR2.A(eVarB);
        pR2.L();
        P pR3 = R();
        io.reactivex.rxjava3.internal.operators.mixed.b bVar3 = new io.reactivex.rxjava3.internal.operators.mixed.b(1, pR3.E().e(new com.google.firebase.crashlytics.internal.common.j(pR3, i)), new com.google.android.material.floatingactionbutton.c(pR3, 23));
        Intrinsics.checkNotNullExpressionValue(bVar3, "flatMapObservable(...)");
        io.reactivex.rxjava3.internal.observers.h hVarD = B7.d(bVar3, new com.quizlet.features.practicetest.navigation.a(22), null, new C4429c(pR3, 2), 2);
        Intrinsics.checkNotNullParameter(hVarD, "<this>");
        pR3.A(hVarD);
        ((AppBarLayout) this.l.getValue()).a(new com.google.android.material.appbar.f() { // from class: com.quizlet.features.setpage.h
            @Override // com.google.android.material.appbar.f
            public final void a(AppBarLayout appBarLayout, int i10) throws Resources.NotFoundException {
                int i11;
                int totalScrollRange = appBarLayout.getTotalScrollRange() + i10;
                r rVar = this.a;
                int i12 = 0;
                boolean z = totalScrollRange <= rVar.Y;
                if (rVar.M != z) {
                    int dimensionPixelSize = rVar.getResources().getDimensionPixelSize(R.dimen.ref_spacing_xsmall);
                    if (z) {
                        i11 = rVar.Y;
                    } else {
                        i11 = 0;
                        i12 = rVar.Y;
                    }
                    ValueAnimator valueAnimator = rVar.V;
                    if (valueAnimator != null) {
                        valueAnimator.cancel();
                    }
                    ValueAnimator duration = ValueAnimator.ofInt(i12, i11).setDuration(200L);
                    rVar.V = duration;
                    if (duration != null) {
                        duration.addUpdateListener(new com.airbnb.lottie.s(rVar, 6));
                    }
                    ValueAnimator valueAnimator2 = rVar.V;
                    if (valueAnimator2 != null) {
                        valueAnimator2.addListener(new q(z, rVar, dimensionPixelSize));
                    }
                    ValueAnimator valueAnimator3 = rVar.V;
                    if (valueAnimator3 != null) {
                        valueAnimator3.start();
                    }
                    rVar.M = z;
                }
            }
        });
        ((AchievementEarnedView) this.v.getValue()).setOnAchievementEventListener((com.quizlet.features.achievements.notification.f) eVar.getValue());
    }

    @Override // com.quizlet.baseui.base.b, androidx.appcompat.app.AbstractActivityC0055k, androidx.fragment.app.I, android.app.Activity
    public void onDestroy() {
        super.onDestroy();
        this.W = null;
    }

    @Override // androidx.activity.s, android.app.Activity
    public final void onNewIntent(Intent intent) {
        Intrinsics.checkNotNullParameter(intent, "intent");
        super.onNewIntent(intent);
        long jD = R().D();
        long longExtra = intent.getLongExtra("setId", jD);
        setIntent(intent);
        if (jD == longExtra) {
            R().L();
            return;
        }
        P pR = R();
        pR.r1 = longExtra;
        pR.A1 = true;
        recreate();
    }

    @Override // com.quizlet.baseui.base.b, androidx.fragment.app.I, android.app.Activity
    public final void onPause() {
        P pR = R();
        pR.I1.a(pR);
        super.onPause();
    }

    @Override // com.quizlet.baseui.base.b, androidx.fragment.app.I, android.app.Activity
    public final void onResume() {
        P pR = R();
        final C0138o c0138o = pR.H1;
        C c = new C(((io.ktor.client.plugins.api.d) c0138o.b).o(c0138o.a, (io.reactivex.rxjava3.subjects.r) c0138o.i), new com.quizlet.analytics.marketing.e(c0138o, 10), io.reactivex.rxjava3.internal.functions.d.c);
        Intrinsics.checkNotNullExpressionValue(c, "doOnSubscribe(...)");
        final int i = 0;
        final int i2 = 1;
        c0138o.g = B7.d(c, new Function1() { // from class: com.quizlet.features.setpage.data.a
            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object obj) {
                switch (i) {
                    case 0:
                        Throwable e = (Throwable) obj;
                        Intrinsics.checkNotNullParameter(e, "e");
                        d dVar = (d) c0138o.h;
                        Object[] args = new Object[0];
                        Intrinsics.checkNotNullParameter(args, "args");
                        dVar.b(new com.quizlet.features.setpage.state.a(new f(R.string.client_error_net_exception, C4933y.P(args))));
                        timber.log.c.a.f(e, "Error trying to retrieve StudySetWithCreator", new Object[0]);
                        break;
                    default:
                        Z1 it2 = (Z1) obj;
                        Intrinsics.checkNotNullParameter(it2, "it");
                        ((d) c0138o.h).b(new com.quizlet.features.setpage.state.c(it2));
                        break;
                }
                return Unit.a;
            }
        }, null, new Function1() { // from class: com.quizlet.features.setpage.data.a
            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object obj) {
                switch (i2) {
                    case 0:
                        Throwable e = (Throwable) obj;
                        Intrinsics.checkNotNullParameter(e, "e");
                        d dVar = (d) c0138o.h;
                        Object[] args = new Object[0];
                        Intrinsics.checkNotNullParameter(args, "args");
                        dVar.b(new com.quizlet.features.setpage.state.a(new f(R.string.client_error_net_exception, C4933y.P(args))));
                        timber.log.c.a.f(e, "Error trying to retrieve StudySetWithCreator", new Object[0]);
                        break;
                    default:
                        Z1 it2 = (Z1) obj;
                        Intrinsics.checkNotNullParameter(it2, "it");
                        ((d) c0138o.h).b(new com.quizlet.features.setpage.state.c(it2));
                        break;
                }
                return Unit.a;
            }
        }, 2);
        ((com.quizlet.features.infra.studysetting.datasource.a) c0138o.d).d();
        ((com.quizlet.features.infra.studysetting.datasource.a) c0138o.e).d();
        ((com.quizlet.features.infra.studysetting.datasource.a) c0138o.f).d();
        pR.I1.e(pR);
        kotlinx.coroutines.E.A(p0.j(pR), pR.J1, null, new C4433g(pR, null), 2);
        com.quizlet.quizletandroid.managers.c cVar = this.w;
        if (cVar == null) {
            Intrinsics.m("conversionTrackingManager");
            throw null;
        }
        Context applicationContext = getApplicationContext();
        Intrinsics.checkNotNullExpressionValue(applicationContext, "getApplicationContext(...)");
        cVar.a.a(new com.quizlet.quizletandroid.managers.a(applicationContext, getIntent().getData()));
        super.onResume();
    }

    @Override // com.quizlet.baseui.base.b, androidx.appcompat.app.AbstractActivityC0055k, androidx.fragment.app.I, android.app.Activity
    public final void onStart() {
        super.onStart();
        y yVar = R().H;
        yVar.f = null;
        yVar.g = null;
    }

    @Override // com.quizlet.baseui.base.b, androidx.appcompat.app.AbstractActivityC0055k, androidx.fragment.app.I, android.app.Activity
    public final void onStop() {
        super.onStop();
        V(false);
    }
}

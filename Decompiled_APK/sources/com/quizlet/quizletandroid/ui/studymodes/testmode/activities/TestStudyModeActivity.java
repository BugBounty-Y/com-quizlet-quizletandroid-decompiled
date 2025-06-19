package com.quizlet.quizletandroid.ui.studymodes.testmode.activities;

import android.content.Intent;
import android.os.Bundle;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import androidx.activity.v;
import androidx.compose.ui.node.B;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.core.view.L;
import androidx.core.view.V;
import androidx.fragment.app.AbstractC1136h0;
import androidx.fragment.app.C1121a;
import androidx.lifecycle.Y;
import androidx.lifecycle.p0;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3110c0;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3242q6;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3675m6;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3699p6;
import com.google.android.gms.internal.mlkit_vision_document_scanner.H6;
import com.quizlet.data.model.InterfaceC4176w0;
import com.quizlet.data.model.o2;
import com.quizlet.db.data.models.persisted.DBSession;
import com.quizlet.features.flashcards.FlashcardsActivity;
import com.quizlet.features.infra.basestudy.data.models.logging.StudyEventLogData;
import com.quizlet.features.infra.studysetting.data.TestStudyModeConfig;
import com.quizlet.features.questiontypes.basequestion.data.ShowQuestion;
import com.quizlet.features.questiontypes.basequestion.j;
import com.quizlet.features.questiontypes.basequestion.k;
import com.quizlet.features.questiontypes.coordinator.QuestionCoordinatorFragment;
import com.quizlet.generated.enums.A1;
import com.quizlet.partskit.widgets.QProgressBar;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.databinding.C4606j;
import com.quizlet.quizletandroid.ui.learnpaywall.LearnPaywallFragment;
import com.quizlet.quizletandroid.ui.studymodes.assistant.LearningAssistantActivity;
import com.quizlet.quizletandroid.ui.studymodes.testmode.fragments.TestModeResultsFragment;
import com.quizlet.quizletandroid.ui.studymodes.testmode.fragments.TestStudyModeResultsLoadingFragment;
import com.quizlet.quizletandroid.ui.studymodes.testmode.models.q;
import com.quizlet.quizletandroid.ui.studymodes.testmode.models.r;
import com.quizlet.quizletandroid.ui.studymodes.testmode.models.s;
import com.quizlet.quizletandroid.ui.studymodes.testmode.models.w;
import com.quizlet.quizletandroid.ui.studymodes.testmode.models.x;
import com.quizlet.quizletandroid.ui.studymodes.testmode.models.y;
import com.quizlet.quizletandroid.ui.studymodes.testmode.start.TestModeStartFragment;
import com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.D;
import com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.G;
import com.quizlet.uicommon.ui.common.dialogs.QAlertDialogFragment;
import com.quizlet.uicommon.ui.common.dialogs.e;
import com.quizlet.uicommon.ui.common.dialogs.h;
import com.quizlet.uicommon.ui.common.dialogs.i;
import com.quizlet.upgrade.ui.activity.UpgradeActivity;
import java.io.Serializable;
import java.util.WeakHashMap;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;
import kotlinx.coroutines.E;

@Metadata
/* loaded from: classes3.dex */
public final class TestStudyModeActivity extends com.quizlet.ads.ui.activity.d {
    public static final String v;
    public static final int w;
    public com.onetrust.otpublishers.headless.UI.viewmodel.c q;
    public final com.quizlet.data.repository.folderwithcreatorinclass.e r;
    public final com.quizlet.data.repository.folderwithcreatorinclass.e s;
    public final com.quizlet.data.repository.folderwithcreatorinclass.e t;
    public androidx.activity.result.b u;

    static {
        Intrinsics.checkNotNullExpressionValue("TestStudyModeActivity", "getSimpleName(...)");
        v = "TestStudyModeActivity";
        w = R.string.test;
    }

    public TestStudyModeActivity() {
        super(12);
        this.r = new com.quizlet.data.repository.folderwithcreatorinclass.e(K.a(G.class), new f(this, 1), new f(this, 0), new f(this, 2));
        this.s = new com.quizlet.data.repository.folderwithcreatorinclass.e(K.a(k.class), new f(this, 4), new f(this, 3), new f(this, 5));
        this.t = new com.quizlet.data.repository.folderwithcreatorinclass.e(K.a(com.quizlet.quizletandroid.ui.learnpaywall.k.class), new f(this, 6), new com.quizlet.quizletandroid.ui.studymodes.assistant.settings.grading.a(this, 6), new f(this, 7));
    }

    @Override // com.quizlet.baseui.base.b
    public final String D() {
        return v;
    }

    @Override // com.quizlet.baseui.base.f
    public final androidx.viewbinding.a N() {
        View viewInflate = getLayoutInflater().inflate(R.layout.activity_test_studymode, (ViewGroup) null, false);
        int i = R.id.back;
        FrameLayout frameLayout = (FrameLayout) AbstractC3375o2.c(R.id.back, viewInflate);
        if (frameLayout != null) {
            i = R.id.fragment_container;
            FrameLayout frameLayout2 = (FrameLayout) AbstractC3375o2.c(R.id.fragment_container, viewInflate);
            if (frameLayout2 != null) {
                i = R.id.test_mode_data_loading_progress_bar;
                if (((ProgressBar) AbstractC3375o2.c(R.id.test_mode_data_loading_progress_bar, viewInflate)) != null) {
                    LinearLayout linearLayout = (LinearLayout) viewInflate;
                    i = R.id.test_progress_bar;
                    QProgressBar qProgressBar = (QProgressBar) AbstractC3375o2.c(R.id.test_progress_bar, viewInflate);
                    if (qProgressBar != null) {
                        i = R.id.test_progress_text;
                        QTextView qTextView = (QTextView) AbstractC3375o2.c(R.id.test_progress_text, viewInflate);
                        if (qTextView != null) {
                            i = R.id.test_toolbar;
                            ConstraintLayout constraintLayout = (ConstraintLayout) AbstractC3375o2.c(R.id.test_toolbar, viewInflate);
                            if (constraintLayout != null) {
                                C4606j c4606j = new C4606j(linearLayout, frameLayout, frameLayout2, linearLayout, qProgressBar, qTextView, constraintLayout);
                                Intrinsics.checkNotNullExpressionValue(c4606j, "inflate(...)");
                                return c4606j;
                            }
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(viewInflate.getResources().getResourceName(i)));
    }

    public final void b0() {
        ((C4606j) K()).e.setProgress(((C4606j) K()).e.getMax());
    }

    public final G c0() {
        return (G) this.r.getValue();
    }

    public final void d0(boolean z, boolean z2) {
        if (!z2 || !z) {
            if (z) {
                Serializable serializableExtra = getIntent().getSerializableExtra("meteredEvent");
                Intrinsics.e(serializableExtra, "null cannot be cast to non-null type com.quizlet.data.model.MeteredEvent");
                Serializable serializableExtra2 = getIntent().getSerializableExtra("learnMeteredEvent");
                Intrinsics.e(serializableExtra2, "null cannot be cast to non-null type com.quizlet.data.model.MeteredEvent");
                Intent intent = new Intent(this, (Class<?>) TestStudyModeActivity.class);
                intent.putExtras(getIntent());
                intent.putExtra("meteredEvent", H6.c((InterfaceC4176w0) serializableExtra));
                intent.putExtra("learnMeteredEvent", H6.c((InterfaceC4176w0) serializableExtra2));
                startActivity(intent);
            }
            finish();
            return;
        }
        G gC0 = c0();
        InterfaceC4176w0 interfaceC4176w0 = gC0.I;
        if (interfaceC4176w0 == null) {
            Intrinsics.m("testMeteredEvent");
            throw null;
        }
        gC0.I = H6.c(interfaceC4176w0);
        InterfaceC4176w0 interfaceC4176w02 = gC0.J;
        if (interfaceC4176w02 == null) {
            Intrinsics.m("learnMeteredEvent");
            throw null;
        }
        o2 o2VarC = H6.c(interfaceC4176w02);
        gC0.J = o2VarC;
        gC0.F = true;
        Y y = gC0.z;
        InterfaceC4176w0 interfaceC4176w03 = gC0.I;
        if (interfaceC4176w03 == null) {
            Intrinsics.m("testMeteredEvent");
            throw null;
        }
        y.j(new y(interfaceC4176w03, o2VarC));
        if (gC0.E == null) {
            throw new IllegalArgumentException("Required value was null.");
        }
        gC0.s.j(r.a);
    }

    @Override // androidx.activity.s, android.app.Activity
    public final void onBackPressed() {
        c0().F();
    }

    @Override // com.quizlet.ads.ui.activity.d, com.quizlet.baseui.base.f, com.quizlet.baseui.base.b, androidx.fragment.app.I, androidx.activity.s, androidx.core.app.AbstractActivityC1021h, android.app.Activity
    public final void onCreate(Bundle bundle) {
        final int i = 4;
        final int i2 = 0;
        super.onCreate(bundle);
        final int i3 = 3;
        v.b(this, null, 3);
        C4606j c4606j = (C4606j) K();
        b bVar = new b(this);
        WeakHashMap weakHashMap = V.a;
        L.m(c4606j.a, bVar);
        Function1 onUpgradeFinished = new Function1(this) { // from class: com.quizlet.quizletandroid.ui.studymodes.testmode.activities.a
            public final /* synthetic */ TestStudyModeActivity b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object obj) {
                int i4 = 3;
                TestStudyModeActivity testStudyModeActivity = this.b;
                switch (i2) {
                    case 0:
                        com.quizlet.upgrade.util.a it2 = (com.quizlet.upgrade.util.a) obj;
                        String str = TestStudyModeActivity.v;
                        Intrinsics.checkNotNullParameter(it2, "it");
                        if (it2.a) {
                            testStudyModeActivity.d0(it2.c, false);
                        }
                        return Unit.a;
                    case 1:
                        x xVar = (x) obj;
                        String str2 = TestStudyModeActivity.v;
                        if (xVar instanceof s) {
                            s sVar = (s) xVar;
                            String str3 = TestModeStartFragment.l;
                            StudyEventLogData studyEventLogData = sVar.a;
                            Intrinsics.checkNotNullParameter(studyEventLogData, "studyEventLogData");
                            InterfaceC4176w0 meteredEvent = sVar.b;
                            Intrinsics.checkNotNullParameter(meteredEvent, "meteredEvent");
                            TestModeStartFragment testModeStartFragment = new TestModeStartFragment();
                            Bundle bundle2 = new Bundle();
                            bundle2.putParcelable("arg_study_event_log_data", studyEventLogData);
                            bundle2.putSerializable("arg_metered_event", meteredEvent);
                            testModeStartFragment.setArguments(bundle2);
                            AbstractC1136h0 supportFragmentManager = testStudyModeActivity.getSupportFragmentManager();
                            C1121a c1121aB = B.b(supportFragmentManager, supportFragmentManager);
                            c1121aB.l(R.id.fragment_container, testModeStartFragment, TestModeStartFragment.l);
                            c1121aB.g();
                        } else if (xVar instanceof q) {
                            q qVar = (q) xVar;
                            j jVar = (j) testStudyModeActivity.s.getValue();
                            ShowQuestion data = qVar.d;
                            k kVar = (k) jVar;
                            kVar.getClass();
                            Intrinsics.checkNotNullParameter(data, "data");
                            kVar.d.j(data);
                            testStudyModeActivity.setTitle((CharSequence) null);
                            int i5 = qVar.a;
                            int i6 = i5 + 1;
                            ConstraintLayout testToolbar = ((C4606j) testStudyModeActivity.K()).g;
                            Intrinsics.checkNotNullExpressionValue(testToolbar, "testToolbar");
                            testToolbar.setVisibility(0);
                            ((C4606j) testStudyModeActivity.K()).e.setProgress(i5);
                            QProgressBar qProgressBar = ((C4606j) testStudyModeActivity.K()).e;
                            int i7 = qVar.b;
                            qProgressBar.setMax(i7);
                            C4606j c4606j2 = (C4606j) testStudyModeActivity.K();
                            c4606j2.f.setText(testStudyModeActivity.getString(R.string.test_new_progress, String.valueOf(i6), String.valueOf(i7)));
                            AbstractC1136h0 supportFragmentManager2 = testStudyModeActivity.getSupportFragmentManager();
                            String str4 = QuestionCoordinatorFragment.k;
                            if (supportFragmentManager2.E(str4) == null) {
                                AbstractC1136h0 supportFragmentManager3 = testStudyModeActivity.getSupportFragmentManager();
                                supportFragmentManager3.getClass();
                                C1121a c1121a = new C1121a(supportFragmentManager3);
                                c1121a.m(0, 0);
                                c1121a.l(R.id.fragment_container, new QuestionCoordinatorFragment(), str4);
                                c1121a.g();
                            }
                            LinearLayout testModeParentLayout = ((C4606j) testStudyModeActivity.K()).d;
                            Intrinsics.checkNotNullExpressionValue(testModeParentLayout, "testModeParentLayout");
                            com.bumptech.glide.c.C(testModeParentLayout, qVar.c);
                        } else if (xVar instanceof r) {
                            ((C4606j) testStudyModeActivity.K()).g.setVisibility(0);
                            testStudyModeActivity.b0();
                            if (testStudyModeActivity.getSupportFragmentManager().E("TestModeResultsFragment") == null) {
                                TestModeResultsFragment testModeResultsFragment = new TestModeResultsFragment();
                                AbstractC1136h0 supportFragmentManager4 = testStudyModeActivity.getSupportFragmentManager();
                                supportFragmentManager4.getClass();
                                C1121a c1121a2 = new C1121a(supportFragmentManager4);
                                c1121a2.m(0, 0);
                                c1121a2.l(R.id.fragment_container, testModeResultsFragment, "TestModeResultsFragment");
                                c1121a2.g();
                            }
                        } else if (xVar instanceof com.quizlet.quizletandroid.ui.studymodes.testmode.models.k) {
                            com.quizlet.quizletandroid.ui.studymodes.testmode.models.k kVar2 = (com.quizlet.quizletandroid.ui.studymodes.testmode.models.k) xVar;
                            testStudyModeActivity.b0();
                            AbstractC1136h0 supportFragmentManager5 = testStudyModeActivity.getSupportFragmentManager();
                            String str5 = LearnPaywallFragment.h;
                            if (supportFragmentManager5.E(str5) == null) {
                                ConstraintLayout testToolbar2 = ((C4606j) testStudyModeActivity.K()).g;
                                Intrinsics.checkNotNullExpressionValue(testToolbar2, "testToolbar");
                                testToolbar2.setVisibility(8);
                                ((com.quizlet.quizletandroid.ui.learnpaywall.k) testStudyModeActivity.t.getValue()).C(kVar2.a, kVar2.b, kVar2.c, kVar2.d);
                                LearnPaywallFragment learnPaywallFragment = new LearnPaywallFragment();
                                AbstractC1136h0 supportFragmentManager6 = testStudyModeActivity.getSupportFragmentManager();
                                supportFragmentManager6.getClass();
                                C1121a c1121a3 = new C1121a(supportFragmentManager6);
                                c1121a3.m(0, 0);
                                c1121a3.l(R.id.fragment_container, learnPaywallFragment, str5);
                                c1121a3.g();
                            }
                        } else {
                            if (!(xVar instanceof com.quizlet.quizletandroid.ui.studymodes.testmode.models.g)) {
                                throw new NoWhenBranchMatchedException();
                            }
                            testStudyModeActivity.b0();
                            TestStudyModeResultsLoadingFragment testStudyModeResultsLoadingFragment = new TestStudyModeResultsLoadingFragment();
                            AbstractC1136h0 supportFragmentManager7 = testStudyModeActivity.getSupportFragmentManager();
                            supportFragmentManager7.getClass();
                            C1121a c1121a4 = new C1121a(supportFragmentManager7);
                            c1121a4.m(0, 0);
                            c1121a4.l(R.id.fragment_container, testStudyModeResultsLoadingFragment, TestStudyModeResultsLoadingFragment.f);
                            c1121a4.g();
                        }
                        return Unit.a;
                    case 2:
                        com.quizlet.quizletandroid.ui.studymodes.testmode.models.v vVar = (com.quizlet.quizletandroid.ui.studymodes.testmode.models.v) obj;
                        String str6 = TestStudyModeActivity.v;
                        boolean z = vVar instanceof com.quizlet.quizletandroid.ui.studymodes.testmode.models.d;
                        TestStudyModeActivity context = this.b;
                        if (z) {
                            com.quizlet.quizletandroid.ui.studymodes.testmode.models.d dVar = (com.quizlet.quizletandroid.ui.studymodes.testmode.models.d) vVar;
                            String str7 = LearningAssistantActivity.D;
                            dVar.getClass();
                            Intent intentB = AbstractC3675m6.b(context, 0, dVar.a, dVar.c, dVar.b, dVar.d, 0, dVar.f, dVar.e, dVar.g);
                            context.finish();
                            context.startActivityForResult(intentB, 205);
                        } else if (vVar instanceof com.quizlet.quizletandroid.ui.studymodes.testmode.models.c) {
                            com.quizlet.quizletandroid.ui.studymodes.testmode.models.c cVar = (com.quizlet.quizletandroid.ui.studymodes.testmode.models.c) vVar;
                            int i8 = cVar.a;
                            String str8 = cVar.d;
                            com.quizlet.features.infra.basestudy.data.models.r rVar = new com.quizlet.features.infra.basestudy.data.models.r(i8, cVar.c, cVar.b, str8, null, cVar.e);
                            String str9 = FlashcardsActivity.j;
                            Intent intentC = AbstractC3110c0.c(context, rVar);
                            context.finish();
                            context.startActivityForResult(intentC, 204);
                        } else if (Intrinsics.b(vVar, com.quizlet.quizletandroid.ui.studymodes.testmode.models.e.a)) {
                            String str10 = UpgradeActivity.v;
                            Intent intentI = AbstractC3242q6.i(context, "test_toast", com.quizlet.features.infra.models.upgrade.a.t);
                            androidx.activity.result.b bVar2 = context.u;
                            if (bVar2 == null) {
                                Intrinsics.m("meteringToastUpgradeResultLauncher");
                                throw null;
                            }
                            bVar2.a(intentI);
                        } else {
                            if (!Intrinsics.b(vVar, com.quizlet.quizletandroid.ui.studymodes.testmode.models.j.a)) {
                                throw new NoWhenBranchMatchedException();
                            }
                            com.facebook.internal.K k = new com.facebook.internal.K(context, 5);
                            com.quizlet.explanations.questiondetail.ui.d dVar2 = new com.quizlet.explanations.questiondetail.ui.d(context, 4);
                            Intrinsics.checkNotNullParameter(context, "context");
                            String message = context.getString(R.string.set_page_feature_offline_blocked_description);
                            Intrinsics.checkNotNullExpressionValue(message, "getString(...)");
                            Intrinsics.checkNotNullParameter(message, "message");
                            String title = context.getString(R.string.set_page_feature_offline_blocked_title);
                            Intrinsics.checkNotNullExpressionValue(title, "getString(...)");
                            Intrinsics.checkNotNullParameter(title, "title");
                            String text = context.getString(R.string.got_it);
                            Intrinsics.checkNotNullExpressionValue(text, "getString(...)");
                            Intrinsics.checkNotNullParameter(text, "text");
                            i iVar = new i(new QAlertDialogFragment.DialogData(message, title, text, null, true, null), dVar2, null, k);
                            String str11 = QAlertDialogFragment.t;
                            h.a(iVar).O(context.getSupportFragmentManager(), QAlertDialogFragment.t);
                        }
                        return Unit.a;
                    case 3:
                        com.quizlet.quizletandroid.ui.studymodes.testmode.models.a aVar = (com.quizlet.quizletandroid.ui.studymodes.testmode.models.a) obj;
                        String str12 = TestStudyModeActivity.v;
                        if (Intrinsics.b(aVar, com.quizlet.quizletandroid.ui.studymodes.testmode.models.f.a)) {
                            e.a aVar2 = new e.a(testStudyModeActivity);
                            aVar2.d = testStudyModeActivity.getResources().getString(R.string.test_mode_start_test_failed_title);
                            aVar2.e = testStudyModeActivity.getResources().getString(R.string.test_mode_start_test_failed_message);
                            aVar2.i = testStudyModeActivity.getResources().getString(R.string.test_mode_start_test_failed_ok);
                            aVar2.j = null;
                            aVar2.g();
                        } else {
                            if (!Intrinsics.b(aVar, com.quizlet.quizletandroid.ui.studymodes.testmode.models.f.b)) {
                                throw new NoWhenBranchMatchedException();
                            }
                            e.a aVar3 = new e.a(testStudyModeActivity);
                            aVar3.c(R.string.test_mode_exit_confirmation);
                            aVar3.e(R.string.yes_dialog_button, new b(testStudyModeActivity));
                            aVar3.d(R.string.cancel_dialog_button, new com.quizlet.quizletandroid.ui.setcreation.imageupload.a(i4));
                            aVar3.b = false;
                            aVar3.g();
                        }
                        return Unit.a;
                    case 4:
                        String str13 = TestStudyModeActivity.v;
                        j jVar2 = (j) testStudyModeActivity.s.getValue();
                        long j = ((w) obj).a;
                        A1 studyModeType = A1.TEST;
                        k kVar3 = (k) jVar2;
                        kVar3.getClass();
                        Intrinsics.checkNotNullParameter(studyModeType, "studyModeType");
                        kVar3.c.a(j, studyModeType);
                        return Unit.a;
                    case 5:
                        String str14 = TestStudyModeActivity.v;
                        if (((Boolean) obj).booleanValue()) {
                            testStudyModeActivity.setResult(115);
                        }
                        testStudyModeActivity.finish();
                        return Unit.a;
                    default:
                        String str15 = TestStudyModeActivity.v;
                        G gC0 = testStudyModeActivity.c0();
                        int i9 = gC0.B + 1;
                        if (i9 >= gC0.e.a.size()) {
                            TestStudyModeConfig testStudyModeConfig = gC0.E;
                            if (testStudyModeConfig == null) {
                                throw new IllegalArgumentException("Required value was null.");
                            }
                            DBSession dBSession = gC0.K;
                            Intrinsics.d(dBSession);
                            E.A(p0.j(gC0), null, null, new com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.y(testStudyModeConfig, gC0, dBSession, null), 3);
                            gC0.G = false;
                            gC0.K = null;
                        } else {
                            gC0.J(i9);
                        }
                        return Unit.a;
                }
            }
        };
        Intrinsics.checkNotNullParameter(this, "activity");
        Intrinsics.checkNotNullParameter(onUpgradeFinished, "onUpgradeFinished");
        this.u = registerForActivityResult(new androidx.activity.result.contract.b(i), new androidx.activity.compose.b(onUpgradeFinished, 9));
        final int i4 = 6;
        ((k) ((j) this.s.getValue())).f.f(this, new com.quizlet.explanations.feedback.ui.fragments.c(25, new Function1(this) { // from class: com.quizlet.quizletandroid.ui.studymodes.testmode.activities.a
            public final /* synthetic */ TestStudyModeActivity b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object obj) {
                int i42 = 3;
                TestStudyModeActivity testStudyModeActivity = this.b;
                switch (i4) {
                    case 0:
                        com.quizlet.upgrade.util.a it2 = (com.quizlet.upgrade.util.a) obj;
                        String str = TestStudyModeActivity.v;
                        Intrinsics.checkNotNullParameter(it2, "it");
                        if (it2.a) {
                            testStudyModeActivity.d0(it2.c, false);
                        }
                        return Unit.a;
                    case 1:
                        x xVar = (x) obj;
                        String str2 = TestStudyModeActivity.v;
                        if (xVar instanceof s) {
                            s sVar = (s) xVar;
                            String str3 = TestModeStartFragment.l;
                            StudyEventLogData studyEventLogData = sVar.a;
                            Intrinsics.checkNotNullParameter(studyEventLogData, "studyEventLogData");
                            InterfaceC4176w0 meteredEvent = sVar.b;
                            Intrinsics.checkNotNullParameter(meteredEvent, "meteredEvent");
                            TestModeStartFragment testModeStartFragment = new TestModeStartFragment();
                            Bundle bundle2 = new Bundle();
                            bundle2.putParcelable("arg_study_event_log_data", studyEventLogData);
                            bundle2.putSerializable("arg_metered_event", meteredEvent);
                            testModeStartFragment.setArguments(bundle2);
                            AbstractC1136h0 supportFragmentManager = testStudyModeActivity.getSupportFragmentManager();
                            C1121a c1121aB = B.b(supportFragmentManager, supportFragmentManager);
                            c1121aB.l(R.id.fragment_container, testModeStartFragment, TestModeStartFragment.l);
                            c1121aB.g();
                        } else if (xVar instanceof q) {
                            q qVar = (q) xVar;
                            j jVar = (j) testStudyModeActivity.s.getValue();
                            ShowQuestion data = qVar.d;
                            k kVar = (k) jVar;
                            kVar.getClass();
                            Intrinsics.checkNotNullParameter(data, "data");
                            kVar.d.j(data);
                            testStudyModeActivity.setTitle((CharSequence) null);
                            int i5 = qVar.a;
                            int i6 = i5 + 1;
                            ConstraintLayout testToolbar = ((C4606j) testStudyModeActivity.K()).g;
                            Intrinsics.checkNotNullExpressionValue(testToolbar, "testToolbar");
                            testToolbar.setVisibility(0);
                            ((C4606j) testStudyModeActivity.K()).e.setProgress(i5);
                            QProgressBar qProgressBar = ((C4606j) testStudyModeActivity.K()).e;
                            int i7 = qVar.b;
                            qProgressBar.setMax(i7);
                            C4606j c4606j2 = (C4606j) testStudyModeActivity.K();
                            c4606j2.f.setText(testStudyModeActivity.getString(R.string.test_new_progress, String.valueOf(i6), String.valueOf(i7)));
                            AbstractC1136h0 supportFragmentManager2 = testStudyModeActivity.getSupportFragmentManager();
                            String str4 = QuestionCoordinatorFragment.k;
                            if (supportFragmentManager2.E(str4) == null) {
                                AbstractC1136h0 supportFragmentManager3 = testStudyModeActivity.getSupportFragmentManager();
                                supportFragmentManager3.getClass();
                                C1121a c1121a = new C1121a(supportFragmentManager3);
                                c1121a.m(0, 0);
                                c1121a.l(R.id.fragment_container, new QuestionCoordinatorFragment(), str4);
                                c1121a.g();
                            }
                            LinearLayout testModeParentLayout = ((C4606j) testStudyModeActivity.K()).d;
                            Intrinsics.checkNotNullExpressionValue(testModeParentLayout, "testModeParentLayout");
                            com.bumptech.glide.c.C(testModeParentLayout, qVar.c);
                        } else if (xVar instanceof r) {
                            ((C4606j) testStudyModeActivity.K()).g.setVisibility(0);
                            testStudyModeActivity.b0();
                            if (testStudyModeActivity.getSupportFragmentManager().E("TestModeResultsFragment") == null) {
                                TestModeResultsFragment testModeResultsFragment = new TestModeResultsFragment();
                                AbstractC1136h0 supportFragmentManager4 = testStudyModeActivity.getSupportFragmentManager();
                                supportFragmentManager4.getClass();
                                C1121a c1121a2 = new C1121a(supportFragmentManager4);
                                c1121a2.m(0, 0);
                                c1121a2.l(R.id.fragment_container, testModeResultsFragment, "TestModeResultsFragment");
                                c1121a2.g();
                            }
                        } else if (xVar instanceof com.quizlet.quizletandroid.ui.studymodes.testmode.models.k) {
                            com.quizlet.quizletandroid.ui.studymodes.testmode.models.k kVar2 = (com.quizlet.quizletandroid.ui.studymodes.testmode.models.k) xVar;
                            testStudyModeActivity.b0();
                            AbstractC1136h0 supportFragmentManager5 = testStudyModeActivity.getSupportFragmentManager();
                            String str5 = LearnPaywallFragment.h;
                            if (supportFragmentManager5.E(str5) == null) {
                                ConstraintLayout testToolbar2 = ((C4606j) testStudyModeActivity.K()).g;
                                Intrinsics.checkNotNullExpressionValue(testToolbar2, "testToolbar");
                                testToolbar2.setVisibility(8);
                                ((com.quizlet.quizletandroid.ui.learnpaywall.k) testStudyModeActivity.t.getValue()).C(kVar2.a, kVar2.b, kVar2.c, kVar2.d);
                                LearnPaywallFragment learnPaywallFragment = new LearnPaywallFragment();
                                AbstractC1136h0 supportFragmentManager6 = testStudyModeActivity.getSupportFragmentManager();
                                supportFragmentManager6.getClass();
                                C1121a c1121a3 = new C1121a(supportFragmentManager6);
                                c1121a3.m(0, 0);
                                c1121a3.l(R.id.fragment_container, learnPaywallFragment, str5);
                                c1121a3.g();
                            }
                        } else {
                            if (!(xVar instanceof com.quizlet.quizletandroid.ui.studymodes.testmode.models.g)) {
                                throw new NoWhenBranchMatchedException();
                            }
                            testStudyModeActivity.b0();
                            TestStudyModeResultsLoadingFragment testStudyModeResultsLoadingFragment = new TestStudyModeResultsLoadingFragment();
                            AbstractC1136h0 supportFragmentManager7 = testStudyModeActivity.getSupportFragmentManager();
                            supportFragmentManager7.getClass();
                            C1121a c1121a4 = new C1121a(supportFragmentManager7);
                            c1121a4.m(0, 0);
                            c1121a4.l(R.id.fragment_container, testStudyModeResultsLoadingFragment, TestStudyModeResultsLoadingFragment.f);
                            c1121a4.g();
                        }
                        return Unit.a;
                    case 2:
                        com.quizlet.quizletandroid.ui.studymodes.testmode.models.v vVar = (com.quizlet.quizletandroid.ui.studymodes.testmode.models.v) obj;
                        String str6 = TestStudyModeActivity.v;
                        boolean z = vVar instanceof com.quizlet.quizletandroid.ui.studymodes.testmode.models.d;
                        TestStudyModeActivity context = this.b;
                        if (z) {
                            com.quizlet.quizletandroid.ui.studymodes.testmode.models.d dVar = (com.quizlet.quizletandroid.ui.studymodes.testmode.models.d) vVar;
                            String str7 = LearningAssistantActivity.D;
                            dVar.getClass();
                            Intent intentB = AbstractC3675m6.b(context, 0, dVar.a, dVar.c, dVar.b, dVar.d, 0, dVar.f, dVar.e, dVar.g);
                            context.finish();
                            context.startActivityForResult(intentB, 205);
                        } else if (vVar instanceof com.quizlet.quizletandroid.ui.studymodes.testmode.models.c) {
                            com.quizlet.quizletandroid.ui.studymodes.testmode.models.c cVar = (com.quizlet.quizletandroid.ui.studymodes.testmode.models.c) vVar;
                            int i8 = cVar.a;
                            String str8 = cVar.d;
                            com.quizlet.features.infra.basestudy.data.models.r rVar = new com.quizlet.features.infra.basestudy.data.models.r(i8, cVar.c, cVar.b, str8, null, cVar.e);
                            String str9 = FlashcardsActivity.j;
                            Intent intentC = AbstractC3110c0.c(context, rVar);
                            context.finish();
                            context.startActivityForResult(intentC, 204);
                        } else if (Intrinsics.b(vVar, com.quizlet.quizletandroid.ui.studymodes.testmode.models.e.a)) {
                            String str10 = UpgradeActivity.v;
                            Intent intentI = AbstractC3242q6.i(context, "test_toast", com.quizlet.features.infra.models.upgrade.a.t);
                            androidx.activity.result.b bVar2 = context.u;
                            if (bVar2 == null) {
                                Intrinsics.m("meteringToastUpgradeResultLauncher");
                                throw null;
                            }
                            bVar2.a(intentI);
                        } else {
                            if (!Intrinsics.b(vVar, com.quizlet.quizletandroid.ui.studymodes.testmode.models.j.a)) {
                                throw new NoWhenBranchMatchedException();
                            }
                            com.facebook.internal.K k = new com.facebook.internal.K(context, 5);
                            com.quizlet.explanations.questiondetail.ui.d dVar2 = new com.quizlet.explanations.questiondetail.ui.d(context, 4);
                            Intrinsics.checkNotNullParameter(context, "context");
                            String message = context.getString(R.string.set_page_feature_offline_blocked_description);
                            Intrinsics.checkNotNullExpressionValue(message, "getString(...)");
                            Intrinsics.checkNotNullParameter(message, "message");
                            String title = context.getString(R.string.set_page_feature_offline_blocked_title);
                            Intrinsics.checkNotNullExpressionValue(title, "getString(...)");
                            Intrinsics.checkNotNullParameter(title, "title");
                            String text = context.getString(R.string.got_it);
                            Intrinsics.checkNotNullExpressionValue(text, "getString(...)");
                            Intrinsics.checkNotNullParameter(text, "text");
                            i iVar = new i(new QAlertDialogFragment.DialogData(message, title, text, null, true, null), dVar2, null, k);
                            String str11 = QAlertDialogFragment.t;
                            h.a(iVar).O(context.getSupportFragmentManager(), QAlertDialogFragment.t);
                        }
                        return Unit.a;
                    case 3:
                        com.quizlet.quizletandroid.ui.studymodes.testmode.models.a aVar = (com.quizlet.quizletandroid.ui.studymodes.testmode.models.a) obj;
                        String str12 = TestStudyModeActivity.v;
                        if (Intrinsics.b(aVar, com.quizlet.quizletandroid.ui.studymodes.testmode.models.f.a)) {
                            e.a aVar2 = new e.a(testStudyModeActivity);
                            aVar2.d = testStudyModeActivity.getResources().getString(R.string.test_mode_start_test_failed_title);
                            aVar2.e = testStudyModeActivity.getResources().getString(R.string.test_mode_start_test_failed_message);
                            aVar2.i = testStudyModeActivity.getResources().getString(R.string.test_mode_start_test_failed_ok);
                            aVar2.j = null;
                            aVar2.g();
                        } else {
                            if (!Intrinsics.b(aVar, com.quizlet.quizletandroid.ui.studymodes.testmode.models.f.b)) {
                                throw new NoWhenBranchMatchedException();
                            }
                            e.a aVar3 = new e.a(testStudyModeActivity);
                            aVar3.c(R.string.test_mode_exit_confirmation);
                            aVar3.e(R.string.yes_dialog_button, new b(testStudyModeActivity));
                            aVar3.d(R.string.cancel_dialog_button, new com.quizlet.quizletandroid.ui.setcreation.imageupload.a(i42));
                            aVar3.b = false;
                            aVar3.g();
                        }
                        return Unit.a;
                    case 4:
                        String str13 = TestStudyModeActivity.v;
                        j jVar2 = (j) testStudyModeActivity.s.getValue();
                        long j = ((w) obj).a;
                        A1 studyModeType = A1.TEST;
                        k kVar3 = (k) jVar2;
                        kVar3.getClass();
                        Intrinsics.checkNotNullParameter(studyModeType, "studyModeType");
                        kVar3.c.a(j, studyModeType);
                        return Unit.a;
                    case 5:
                        String str14 = TestStudyModeActivity.v;
                        if (((Boolean) obj).booleanValue()) {
                            testStudyModeActivity.setResult(115);
                        }
                        testStudyModeActivity.finish();
                        return Unit.a;
                    default:
                        String str15 = TestStudyModeActivity.v;
                        G gC0 = testStudyModeActivity.c0();
                        int i9 = gC0.B + 1;
                        if (i9 >= gC0.e.a.size()) {
                            TestStudyModeConfig testStudyModeConfig = gC0.E;
                            if (testStudyModeConfig == null) {
                                throw new IllegalArgumentException("Required value was null.");
                            }
                            DBSession dBSession = gC0.K;
                            Intrinsics.d(dBSession);
                            E.A(p0.j(gC0), null, null, new com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.y(testStudyModeConfig, gC0, dBSession, null), 3);
                            gC0.G = false;
                            gC0.K = null;
                        } else {
                            gC0.J(i9);
                        }
                        return Unit.a;
                }
            }
        }));
        final int i5 = 1;
        c0().s.f(this, new com.quizlet.explanations.feedback.ui.fragments.c(25, new Function1(this) { // from class: com.quizlet.quizletandroid.ui.studymodes.testmode.activities.a
            public final /* synthetic */ TestStudyModeActivity b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object obj) {
                int i42 = 3;
                TestStudyModeActivity testStudyModeActivity = this.b;
                switch (i5) {
                    case 0:
                        com.quizlet.upgrade.util.a it2 = (com.quizlet.upgrade.util.a) obj;
                        String str = TestStudyModeActivity.v;
                        Intrinsics.checkNotNullParameter(it2, "it");
                        if (it2.a) {
                            testStudyModeActivity.d0(it2.c, false);
                        }
                        return Unit.a;
                    case 1:
                        x xVar = (x) obj;
                        String str2 = TestStudyModeActivity.v;
                        if (xVar instanceof s) {
                            s sVar = (s) xVar;
                            String str3 = TestModeStartFragment.l;
                            StudyEventLogData studyEventLogData = sVar.a;
                            Intrinsics.checkNotNullParameter(studyEventLogData, "studyEventLogData");
                            InterfaceC4176w0 meteredEvent = sVar.b;
                            Intrinsics.checkNotNullParameter(meteredEvent, "meteredEvent");
                            TestModeStartFragment testModeStartFragment = new TestModeStartFragment();
                            Bundle bundle2 = new Bundle();
                            bundle2.putParcelable("arg_study_event_log_data", studyEventLogData);
                            bundle2.putSerializable("arg_metered_event", meteredEvent);
                            testModeStartFragment.setArguments(bundle2);
                            AbstractC1136h0 supportFragmentManager = testStudyModeActivity.getSupportFragmentManager();
                            C1121a c1121aB = B.b(supportFragmentManager, supportFragmentManager);
                            c1121aB.l(R.id.fragment_container, testModeStartFragment, TestModeStartFragment.l);
                            c1121aB.g();
                        } else if (xVar instanceof q) {
                            q qVar = (q) xVar;
                            j jVar = (j) testStudyModeActivity.s.getValue();
                            ShowQuestion data = qVar.d;
                            k kVar = (k) jVar;
                            kVar.getClass();
                            Intrinsics.checkNotNullParameter(data, "data");
                            kVar.d.j(data);
                            testStudyModeActivity.setTitle((CharSequence) null);
                            int i52 = qVar.a;
                            int i6 = i52 + 1;
                            ConstraintLayout testToolbar = ((C4606j) testStudyModeActivity.K()).g;
                            Intrinsics.checkNotNullExpressionValue(testToolbar, "testToolbar");
                            testToolbar.setVisibility(0);
                            ((C4606j) testStudyModeActivity.K()).e.setProgress(i52);
                            QProgressBar qProgressBar = ((C4606j) testStudyModeActivity.K()).e;
                            int i7 = qVar.b;
                            qProgressBar.setMax(i7);
                            C4606j c4606j2 = (C4606j) testStudyModeActivity.K();
                            c4606j2.f.setText(testStudyModeActivity.getString(R.string.test_new_progress, String.valueOf(i6), String.valueOf(i7)));
                            AbstractC1136h0 supportFragmentManager2 = testStudyModeActivity.getSupportFragmentManager();
                            String str4 = QuestionCoordinatorFragment.k;
                            if (supportFragmentManager2.E(str4) == null) {
                                AbstractC1136h0 supportFragmentManager3 = testStudyModeActivity.getSupportFragmentManager();
                                supportFragmentManager3.getClass();
                                C1121a c1121a = new C1121a(supportFragmentManager3);
                                c1121a.m(0, 0);
                                c1121a.l(R.id.fragment_container, new QuestionCoordinatorFragment(), str4);
                                c1121a.g();
                            }
                            LinearLayout testModeParentLayout = ((C4606j) testStudyModeActivity.K()).d;
                            Intrinsics.checkNotNullExpressionValue(testModeParentLayout, "testModeParentLayout");
                            com.bumptech.glide.c.C(testModeParentLayout, qVar.c);
                        } else if (xVar instanceof r) {
                            ((C4606j) testStudyModeActivity.K()).g.setVisibility(0);
                            testStudyModeActivity.b0();
                            if (testStudyModeActivity.getSupportFragmentManager().E("TestModeResultsFragment") == null) {
                                TestModeResultsFragment testModeResultsFragment = new TestModeResultsFragment();
                                AbstractC1136h0 supportFragmentManager4 = testStudyModeActivity.getSupportFragmentManager();
                                supportFragmentManager4.getClass();
                                C1121a c1121a2 = new C1121a(supportFragmentManager4);
                                c1121a2.m(0, 0);
                                c1121a2.l(R.id.fragment_container, testModeResultsFragment, "TestModeResultsFragment");
                                c1121a2.g();
                            }
                        } else if (xVar instanceof com.quizlet.quizletandroid.ui.studymodes.testmode.models.k) {
                            com.quizlet.quizletandroid.ui.studymodes.testmode.models.k kVar2 = (com.quizlet.quizletandroid.ui.studymodes.testmode.models.k) xVar;
                            testStudyModeActivity.b0();
                            AbstractC1136h0 supportFragmentManager5 = testStudyModeActivity.getSupportFragmentManager();
                            String str5 = LearnPaywallFragment.h;
                            if (supportFragmentManager5.E(str5) == null) {
                                ConstraintLayout testToolbar2 = ((C4606j) testStudyModeActivity.K()).g;
                                Intrinsics.checkNotNullExpressionValue(testToolbar2, "testToolbar");
                                testToolbar2.setVisibility(8);
                                ((com.quizlet.quizletandroid.ui.learnpaywall.k) testStudyModeActivity.t.getValue()).C(kVar2.a, kVar2.b, kVar2.c, kVar2.d);
                                LearnPaywallFragment learnPaywallFragment = new LearnPaywallFragment();
                                AbstractC1136h0 supportFragmentManager6 = testStudyModeActivity.getSupportFragmentManager();
                                supportFragmentManager6.getClass();
                                C1121a c1121a3 = new C1121a(supportFragmentManager6);
                                c1121a3.m(0, 0);
                                c1121a3.l(R.id.fragment_container, learnPaywallFragment, str5);
                                c1121a3.g();
                            }
                        } else {
                            if (!(xVar instanceof com.quizlet.quizletandroid.ui.studymodes.testmode.models.g)) {
                                throw new NoWhenBranchMatchedException();
                            }
                            testStudyModeActivity.b0();
                            TestStudyModeResultsLoadingFragment testStudyModeResultsLoadingFragment = new TestStudyModeResultsLoadingFragment();
                            AbstractC1136h0 supportFragmentManager7 = testStudyModeActivity.getSupportFragmentManager();
                            supportFragmentManager7.getClass();
                            C1121a c1121a4 = new C1121a(supportFragmentManager7);
                            c1121a4.m(0, 0);
                            c1121a4.l(R.id.fragment_container, testStudyModeResultsLoadingFragment, TestStudyModeResultsLoadingFragment.f);
                            c1121a4.g();
                        }
                        return Unit.a;
                    case 2:
                        com.quizlet.quizletandroid.ui.studymodes.testmode.models.v vVar = (com.quizlet.quizletandroid.ui.studymodes.testmode.models.v) obj;
                        String str6 = TestStudyModeActivity.v;
                        boolean z = vVar instanceof com.quizlet.quizletandroid.ui.studymodes.testmode.models.d;
                        TestStudyModeActivity context = this.b;
                        if (z) {
                            com.quizlet.quizletandroid.ui.studymodes.testmode.models.d dVar = (com.quizlet.quizletandroid.ui.studymodes.testmode.models.d) vVar;
                            String str7 = LearningAssistantActivity.D;
                            dVar.getClass();
                            Intent intentB = AbstractC3675m6.b(context, 0, dVar.a, dVar.c, dVar.b, dVar.d, 0, dVar.f, dVar.e, dVar.g);
                            context.finish();
                            context.startActivityForResult(intentB, 205);
                        } else if (vVar instanceof com.quizlet.quizletandroid.ui.studymodes.testmode.models.c) {
                            com.quizlet.quizletandroid.ui.studymodes.testmode.models.c cVar = (com.quizlet.quizletandroid.ui.studymodes.testmode.models.c) vVar;
                            int i8 = cVar.a;
                            String str8 = cVar.d;
                            com.quizlet.features.infra.basestudy.data.models.r rVar = new com.quizlet.features.infra.basestudy.data.models.r(i8, cVar.c, cVar.b, str8, null, cVar.e);
                            String str9 = FlashcardsActivity.j;
                            Intent intentC = AbstractC3110c0.c(context, rVar);
                            context.finish();
                            context.startActivityForResult(intentC, 204);
                        } else if (Intrinsics.b(vVar, com.quizlet.quizletandroid.ui.studymodes.testmode.models.e.a)) {
                            String str10 = UpgradeActivity.v;
                            Intent intentI = AbstractC3242q6.i(context, "test_toast", com.quizlet.features.infra.models.upgrade.a.t);
                            androidx.activity.result.b bVar2 = context.u;
                            if (bVar2 == null) {
                                Intrinsics.m("meteringToastUpgradeResultLauncher");
                                throw null;
                            }
                            bVar2.a(intentI);
                        } else {
                            if (!Intrinsics.b(vVar, com.quizlet.quizletandroid.ui.studymodes.testmode.models.j.a)) {
                                throw new NoWhenBranchMatchedException();
                            }
                            com.facebook.internal.K k = new com.facebook.internal.K(context, 5);
                            com.quizlet.explanations.questiondetail.ui.d dVar2 = new com.quizlet.explanations.questiondetail.ui.d(context, 4);
                            Intrinsics.checkNotNullParameter(context, "context");
                            String message = context.getString(R.string.set_page_feature_offline_blocked_description);
                            Intrinsics.checkNotNullExpressionValue(message, "getString(...)");
                            Intrinsics.checkNotNullParameter(message, "message");
                            String title = context.getString(R.string.set_page_feature_offline_blocked_title);
                            Intrinsics.checkNotNullExpressionValue(title, "getString(...)");
                            Intrinsics.checkNotNullParameter(title, "title");
                            String text = context.getString(R.string.got_it);
                            Intrinsics.checkNotNullExpressionValue(text, "getString(...)");
                            Intrinsics.checkNotNullParameter(text, "text");
                            i iVar = new i(new QAlertDialogFragment.DialogData(message, title, text, null, true, null), dVar2, null, k);
                            String str11 = QAlertDialogFragment.t;
                            h.a(iVar).O(context.getSupportFragmentManager(), QAlertDialogFragment.t);
                        }
                        return Unit.a;
                    case 3:
                        com.quizlet.quizletandroid.ui.studymodes.testmode.models.a aVar = (com.quizlet.quizletandroid.ui.studymodes.testmode.models.a) obj;
                        String str12 = TestStudyModeActivity.v;
                        if (Intrinsics.b(aVar, com.quizlet.quizletandroid.ui.studymodes.testmode.models.f.a)) {
                            e.a aVar2 = new e.a(testStudyModeActivity);
                            aVar2.d = testStudyModeActivity.getResources().getString(R.string.test_mode_start_test_failed_title);
                            aVar2.e = testStudyModeActivity.getResources().getString(R.string.test_mode_start_test_failed_message);
                            aVar2.i = testStudyModeActivity.getResources().getString(R.string.test_mode_start_test_failed_ok);
                            aVar2.j = null;
                            aVar2.g();
                        } else {
                            if (!Intrinsics.b(aVar, com.quizlet.quizletandroid.ui.studymodes.testmode.models.f.b)) {
                                throw new NoWhenBranchMatchedException();
                            }
                            e.a aVar3 = new e.a(testStudyModeActivity);
                            aVar3.c(R.string.test_mode_exit_confirmation);
                            aVar3.e(R.string.yes_dialog_button, new b(testStudyModeActivity));
                            aVar3.d(R.string.cancel_dialog_button, new com.quizlet.quizletandroid.ui.setcreation.imageupload.a(i42));
                            aVar3.b = false;
                            aVar3.g();
                        }
                        return Unit.a;
                    case 4:
                        String str13 = TestStudyModeActivity.v;
                        j jVar2 = (j) testStudyModeActivity.s.getValue();
                        long j = ((w) obj).a;
                        A1 studyModeType = A1.TEST;
                        k kVar3 = (k) jVar2;
                        kVar3.getClass();
                        Intrinsics.checkNotNullParameter(studyModeType, "studyModeType");
                        kVar3.c.a(j, studyModeType);
                        return Unit.a;
                    case 5:
                        String str14 = TestStudyModeActivity.v;
                        if (((Boolean) obj).booleanValue()) {
                            testStudyModeActivity.setResult(115);
                        }
                        testStudyModeActivity.finish();
                        return Unit.a;
                    default:
                        String str15 = TestStudyModeActivity.v;
                        G gC0 = testStudyModeActivity.c0();
                        int i9 = gC0.B + 1;
                        if (i9 >= gC0.e.a.size()) {
                            TestStudyModeConfig testStudyModeConfig = gC0.E;
                            if (testStudyModeConfig == null) {
                                throw new IllegalArgumentException("Required value was null.");
                            }
                            DBSession dBSession = gC0.K;
                            Intrinsics.d(dBSession);
                            E.A(p0.j(gC0), null, null, new com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.y(testStudyModeConfig, gC0, dBSession, null), 3);
                            gC0.G = false;
                            gC0.K = null;
                        } else {
                            gC0.J(i9);
                        }
                        return Unit.a;
                }
            }
        }));
        final int i6 = 2;
        c0().A.f(this, new com.quizlet.explanations.feedback.ui.fragments.c(25, new Function1(this) { // from class: com.quizlet.quizletandroid.ui.studymodes.testmode.activities.a
            public final /* synthetic */ TestStudyModeActivity b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object obj) {
                int i42 = 3;
                TestStudyModeActivity testStudyModeActivity = this.b;
                switch (i6) {
                    case 0:
                        com.quizlet.upgrade.util.a it2 = (com.quizlet.upgrade.util.a) obj;
                        String str = TestStudyModeActivity.v;
                        Intrinsics.checkNotNullParameter(it2, "it");
                        if (it2.a) {
                            testStudyModeActivity.d0(it2.c, false);
                        }
                        return Unit.a;
                    case 1:
                        x xVar = (x) obj;
                        String str2 = TestStudyModeActivity.v;
                        if (xVar instanceof s) {
                            s sVar = (s) xVar;
                            String str3 = TestModeStartFragment.l;
                            StudyEventLogData studyEventLogData = sVar.a;
                            Intrinsics.checkNotNullParameter(studyEventLogData, "studyEventLogData");
                            InterfaceC4176w0 meteredEvent = sVar.b;
                            Intrinsics.checkNotNullParameter(meteredEvent, "meteredEvent");
                            TestModeStartFragment testModeStartFragment = new TestModeStartFragment();
                            Bundle bundle2 = new Bundle();
                            bundle2.putParcelable("arg_study_event_log_data", studyEventLogData);
                            bundle2.putSerializable("arg_metered_event", meteredEvent);
                            testModeStartFragment.setArguments(bundle2);
                            AbstractC1136h0 supportFragmentManager = testStudyModeActivity.getSupportFragmentManager();
                            C1121a c1121aB = B.b(supportFragmentManager, supportFragmentManager);
                            c1121aB.l(R.id.fragment_container, testModeStartFragment, TestModeStartFragment.l);
                            c1121aB.g();
                        } else if (xVar instanceof q) {
                            q qVar = (q) xVar;
                            j jVar = (j) testStudyModeActivity.s.getValue();
                            ShowQuestion data = qVar.d;
                            k kVar = (k) jVar;
                            kVar.getClass();
                            Intrinsics.checkNotNullParameter(data, "data");
                            kVar.d.j(data);
                            testStudyModeActivity.setTitle((CharSequence) null);
                            int i52 = qVar.a;
                            int i62 = i52 + 1;
                            ConstraintLayout testToolbar = ((C4606j) testStudyModeActivity.K()).g;
                            Intrinsics.checkNotNullExpressionValue(testToolbar, "testToolbar");
                            testToolbar.setVisibility(0);
                            ((C4606j) testStudyModeActivity.K()).e.setProgress(i52);
                            QProgressBar qProgressBar = ((C4606j) testStudyModeActivity.K()).e;
                            int i7 = qVar.b;
                            qProgressBar.setMax(i7);
                            C4606j c4606j2 = (C4606j) testStudyModeActivity.K();
                            c4606j2.f.setText(testStudyModeActivity.getString(R.string.test_new_progress, String.valueOf(i62), String.valueOf(i7)));
                            AbstractC1136h0 supportFragmentManager2 = testStudyModeActivity.getSupportFragmentManager();
                            String str4 = QuestionCoordinatorFragment.k;
                            if (supportFragmentManager2.E(str4) == null) {
                                AbstractC1136h0 supportFragmentManager3 = testStudyModeActivity.getSupportFragmentManager();
                                supportFragmentManager3.getClass();
                                C1121a c1121a = new C1121a(supportFragmentManager3);
                                c1121a.m(0, 0);
                                c1121a.l(R.id.fragment_container, new QuestionCoordinatorFragment(), str4);
                                c1121a.g();
                            }
                            LinearLayout testModeParentLayout = ((C4606j) testStudyModeActivity.K()).d;
                            Intrinsics.checkNotNullExpressionValue(testModeParentLayout, "testModeParentLayout");
                            com.bumptech.glide.c.C(testModeParentLayout, qVar.c);
                        } else if (xVar instanceof r) {
                            ((C4606j) testStudyModeActivity.K()).g.setVisibility(0);
                            testStudyModeActivity.b0();
                            if (testStudyModeActivity.getSupportFragmentManager().E("TestModeResultsFragment") == null) {
                                TestModeResultsFragment testModeResultsFragment = new TestModeResultsFragment();
                                AbstractC1136h0 supportFragmentManager4 = testStudyModeActivity.getSupportFragmentManager();
                                supportFragmentManager4.getClass();
                                C1121a c1121a2 = new C1121a(supportFragmentManager4);
                                c1121a2.m(0, 0);
                                c1121a2.l(R.id.fragment_container, testModeResultsFragment, "TestModeResultsFragment");
                                c1121a2.g();
                            }
                        } else if (xVar instanceof com.quizlet.quizletandroid.ui.studymodes.testmode.models.k) {
                            com.quizlet.quizletandroid.ui.studymodes.testmode.models.k kVar2 = (com.quizlet.quizletandroid.ui.studymodes.testmode.models.k) xVar;
                            testStudyModeActivity.b0();
                            AbstractC1136h0 supportFragmentManager5 = testStudyModeActivity.getSupportFragmentManager();
                            String str5 = LearnPaywallFragment.h;
                            if (supportFragmentManager5.E(str5) == null) {
                                ConstraintLayout testToolbar2 = ((C4606j) testStudyModeActivity.K()).g;
                                Intrinsics.checkNotNullExpressionValue(testToolbar2, "testToolbar");
                                testToolbar2.setVisibility(8);
                                ((com.quizlet.quizletandroid.ui.learnpaywall.k) testStudyModeActivity.t.getValue()).C(kVar2.a, kVar2.b, kVar2.c, kVar2.d);
                                LearnPaywallFragment learnPaywallFragment = new LearnPaywallFragment();
                                AbstractC1136h0 supportFragmentManager6 = testStudyModeActivity.getSupportFragmentManager();
                                supportFragmentManager6.getClass();
                                C1121a c1121a3 = new C1121a(supportFragmentManager6);
                                c1121a3.m(0, 0);
                                c1121a3.l(R.id.fragment_container, learnPaywallFragment, str5);
                                c1121a3.g();
                            }
                        } else {
                            if (!(xVar instanceof com.quizlet.quizletandroid.ui.studymodes.testmode.models.g)) {
                                throw new NoWhenBranchMatchedException();
                            }
                            testStudyModeActivity.b0();
                            TestStudyModeResultsLoadingFragment testStudyModeResultsLoadingFragment = new TestStudyModeResultsLoadingFragment();
                            AbstractC1136h0 supportFragmentManager7 = testStudyModeActivity.getSupportFragmentManager();
                            supportFragmentManager7.getClass();
                            C1121a c1121a4 = new C1121a(supportFragmentManager7);
                            c1121a4.m(0, 0);
                            c1121a4.l(R.id.fragment_container, testStudyModeResultsLoadingFragment, TestStudyModeResultsLoadingFragment.f);
                            c1121a4.g();
                        }
                        return Unit.a;
                    case 2:
                        com.quizlet.quizletandroid.ui.studymodes.testmode.models.v vVar = (com.quizlet.quizletandroid.ui.studymodes.testmode.models.v) obj;
                        String str6 = TestStudyModeActivity.v;
                        boolean z = vVar instanceof com.quizlet.quizletandroid.ui.studymodes.testmode.models.d;
                        TestStudyModeActivity context = this.b;
                        if (z) {
                            com.quizlet.quizletandroid.ui.studymodes.testmode.models.d dVar = (com.quizlet.quizletandroid.ui.studymodes.testmode.models.d) vVar;
                            String str7 = LearningAssistantActivity.D;
                            dVar.getClass();
                            Intent intentB = AbstractC3675m6.b(context, 0, dVar.a, dVar.c, dVar.b, dVar.d, 0, dVar.f, dVar.e, dVar.g);
                            context.finish();
                            context.startActivityForResult(intentB, 205);
                        } else if (vVar instanceof com.quizlet.quizletandroid.ui.studymodes.testmode.models.c) {
                            com.quizlet.quizletandroid.ui.studymodes.testmode.models.c cVar = (com.quizlet.quizletandroid.ui.studymodes.testmode.models.c) vVar;
                            int i8 = cVar.a;
                            String str8 = cVar.d;
                            com.quizlet.features.infra.basestudy.data.models.r rVar = new com.quizlet.features.infra.basestudy.data.models.r(i8, cVar.c, cVar.b, str8, null, cVar.e);
                            String str9 = FlashcardsActivity.j;
                            Intent intentC = AbstractC3110c0.c(context, rVar);
                            context.finish();
                            context.startActivityForResult(intentC, 204);
                        } else if (Intrinsics.b(vVar, com.quizlet.quizletandroid.ui.studymodes.testmode.models.e.a)) {
                            String str10 = UpgradeActivity.v;
                            Intent intentI = AbstractC3242q6.i(context, "test_toast", com.quizlet.features.infra.models.upgrade.a.t);
                            androidx.activity.result.b bVar2 = context.u;
                            if (bVar2 == null) {
                                Intrinsics.m("meteringToastUpgradeResultLauncher");
                                throw null;
                            }
                            bVar2.a(intentI);
                        } else {
                            if (!Intrinsics.b(vVar, com.quizlet.quizletandroid.ui.studymodes.testmode.models.j.a)) {
                                throw new NoWhenBranchMatchedException();
                            }
                            com.facebook.internal.K k = new com.facebook.internal.K(context, 5);
                            com.quizlet.explanations.questiondetail.ui.d dVar2 = new com.quizlet.explanations.questiondetail.ui.d(context, 4);
                            Intrinsics.checkNotNullParameter(context, "context");
                            String message = context.getString(R.string.set_page_feature_offline_blocked_description);
                            Intrinsics.checkNotNullExpressionValue(message, "getString(...)");
                            Intrinsics.checkNotNullParameter(message, "message");
                            String title = context.getString(R.string.set_page_feature_offline_blocked_title);
                            Intrinsics.checkNotNullExpressionValue(title, "getString(...)");
                            Intrinsics.checkNotNullParameter(title, "title");
                            String text = context.getString(R.string.got_it);
                            Intrinsics.checkNotNullExpressionValue(text, "getString(...)");
                            Intrinsics.checkNotNullParameter(text, "text");
                            i iVar = new i(new QAlertDialogFragment.DialogData(message, title, text, null, true, null), dVar2, null, k);
                            String str11 = QAlertDialogFragment.t;
                            h.a(iVar).O(context.getSupportFragmentManager(), QAlertDialogFragment.t);
                        }
                        return Unit.a;
                    case 3:
                        com.quizlet.quizletandroid.ui.studymodes.testmode.models.a aVar = (com.quizlet.quizletandroid.ui.studymodes.testmode.models.a) obj;
                        String str12 = TestStudyModeActivity.v;
                        if (Intrinsics.b(aVar, com.quizlet.quizletandroid.ui.studymodes.testmode.models.f.a)) {
                            e.a aVar2 = new e.a(testStudyModeActivity);
                            aVar2.d = testStudyModeActivity.getResources().getString(R.string.test_mode_start_test_failed_title);
                            aVar2.e = testStudyModeActivity.getResources().getString(R.string.test_mode_start_test_failed_message);
                            aVar2.i = testStudyModeActivity.getResources().getString(R.string.test_mode_start_test_failed_ok);
                            aVar2.j = null;
                            aVar2.g();
                        } else {
                            if (!Intrinsics.b(aVar, com.quizlet.quizletandroid.ui.studymodes.testmode.models.f.b)) {
                                throw new NoWhenBranchMatchedException();
                            }
                            e.a aVar3 = new e.a(testStudyModeActivity);
                            aVar3.c(R.string.test_mode_exit_confirmation);
                            aVar3.e(R.string.yes_dialog_button, new b(testStudyModeActivity));
                            aVar3.d(R.string.cancel_dialog_button, new com.quizlet.quizletandroid.ui.setcreation.imageupload.a(i42));
                            aVar3.b = false;
                            aVar3.g();
                        }
                        return Unit.a;
                    case 4:
                        String str13 = TestStudyModeActivity.v;
                        j jVar2 = (j) testStudyModeActivity.s.getValue();
                        long j = ((w) obj).a;
                        A1 studyModeType = A1.TEST;
                        k kVar3 = (k) jVar2;
                        kVar3.getClass();
                        Intrinsics.checkNotNullParameter(studyModeType, "studyModeType");
                        kVar3.c.a(j, studyModeType);
                        return Unit.a;
                    case 5:
                        String str14 = TestStudyModeActivity.v;
                        if (((Boolean) obj).booleanValue()) {
                            testStudyModeActivity.setResult(115);
                        }
                        testStudyModeActivity.finish();
                        return Unit.a;
                    default:
                        String str15 = TestStudyModeActivity.v;
                        G gC0 = testStudyModeActivity.c0();
                        int i9 = gC0.B + 1;
                        if (i9 >= gC0.e.a.size()) {
                            TestStudyModeConfig testStudyModeConfig = gC0.E;
                            if (testStudyModeConfig == null) {
                                throw new IllegalArgumentException("Required value was null.");
                            }
                            DBSession dBSession = gC0.K;
                            Intrinsics.d(dBSession);
                            E.A(p0.j(gC0), null, null, new com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.y(testStudyModeConfig, gC0, dBSession, null), 3);
                            gC0.G = false;
                            gC0.K = null;
                        } else {
                            gC0.J(i9);
                        }
                        return Unit.a;
                }
            }
        }));
        c0().w.f(this, new com.quizlet.explanations.feedback.ui.fragments.c(25, new Function1(this) { // from class: com.quizlet.quizletandroid.ui.studymodes.testmode.activities.a
            public final /* synthetic */ TestStudyModeActivity b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object obj) {
                int i42 = 3;
                TestStudyModeActivity testStudyModeActivity = this.b;
                switch (i3) {
                    case 0:
                        com.quizlet.upgrade.util.a it2 = (com.quizlet.upgrade.util.a) obj;
                        String str = TestStudyModeActivity.v;
                        Intrinsics.checkNotNullParameter(it2, "it");
                        if (it2.a) {
                            testStudyModeActivity.d0(it2.c, false);
                        }
                        return Unit.a;
                    case 1:
                        x xVar = (x) obj;
                        String str2 = TestStudyModeActivity.v;
                        if (xVar instanceof s) {
                            s sVar = (s) xVar;
                            String str3 = TestModeStartFragment.l;
                            StudyEventLogData studyEventLogData = sVar.a;
                            Intrinsics.checkNotNullParameter(studyEventLogData, "studyEventLogData");
                            InterfaceC4176w0 meteredEvent = sVar.b;
                            Intrinsics.checkNotNullParameter(meteredEvent, "meteredEvent");
                            TestModeStartFragment testModeStartFragment = new TestModeStartFragment();
                            Bundle bundle2 = new Bundle();
                            bundle2.putParcelable("arg_study_event_log_data", studyEventLogData);
                            bundle2.putSerializable("arg_metered_event", meteredEvent);
                            testModeStartFragment.setArguments(bundle2);
                            AbstractC1136h0 supportFragmentManager = testStudyModeActivity.getSupportFragmentManager();
                            C1121a c1121aB = B.b(supportFragmentManager, supportFragmentManager);
                            c1121aB.l(R.id.fragment_container, testModeStartFragment, TestModeStartFragment.l);
                            c1121aB.g();
                        } else if (xVar instanceof q) {
                            q qVar = (q) xVar;
                            j jVar = (j) testStudyModeActivity.s.getValue();
                            ShowQuestion data = qVar.d;
                            k kVar = (k) jVar;
                            kVar.getClass();
                            Intrinsics.checkNotNullParameter(data, "data");
                            kVar.d.j(data);
                            testStudyModeActivity.setTitle((CharSequence) null);
                            int i52 = qVar.a;
                            int i62 = i52 + 1;
                            ConstraintLayout testToolbar = ((C4606j) testStudyModeActivity.K()).g;
                            Intrinsics.checkNotNullExpressionValue(testToolbar, "testToolbar");
                            testToolbar.setVisibility(0);
                            ((C4606j) testStudyModeActivity.K()).e.setProgress(i52);
                            QProgressBar qProgressBar = ((C4606j) testStudyModeActivity.K()).e;
                            int i7 = qVar.b;
                            qProgressBar.setMax(i7);
                            C4606j c4606j2 = (C4606j) testStudyModeActivity.K();
                            c4606j2.f.setText(testStudyModeActivity.getString(R.string.test_new_progress, String.valueOf(i62), String.valueOf(i7)));
                            AbstractC1136h0 supportFragmentManager2 = testStudyModeActivity.getSupportFragmentManager();
                            String str4 = QuestionCoordinatorFragment.k;
                            if (supportFragmentManager2.E(str4) == null) {
                                AbstractC1136h0 supportFragmentManager3 = testStudyModeActivity.getSupportFragmentManager();
                                supportFragmentManager3.getClass();
                                C1121a c1121a = new C1121a(supportFragmentManager3);
                                c1121a.m(0, 0);
                                c1121a.l(R.id.fragment_container, new QuestionCoordinatorFragment(), str4);
                                c1121a.g();
                            }
                            LinearLayout testModeParentLayout = ((C4606j) testStudyModeActivity.K()).d;
                            Intrinsics.checkNotNullExpressionValue(testModeParentLayout, "testModeParentLayout");
                            com.bumptech.glide.c.C(testModeParentLayout, qVar.c);
                        } else if (xVar instanceof r) {
                            ((C4606j) testStudyModeActivity.K()).g.setVisibility(0);
                            testStudyModeActivity.b0();
                            if (testStudyModeActivity.getSupportFragmentManager().E("TestModeResultsFragment") == null) {
                                TestModeResultsFragment testModeResultsFragment = new TestModeResultsFragment();
                                AbstractC1136h0 supportFragmentManager4 = testStudyModeActivity.getSupportFragmentManager();
                                supportFragmentManager4.getClass();
                                C1121a c1121a2 = new C1121a(supportFragmentManager4);
                                c1121a2.m(0, 0);
                                c1121a2.l(R.id.fragment_container, testModeResultsFragment, "TestModeResultsFragment");
                                c1121a2.g();
                            }
                        } else if (xVar instanceof com.quizlet.quizletandroid.ui.studymodes.testmode.models.k) {
                            com.quizlet.quizletandroid.ui.studymodes.testmode.models.k kVar2 = (com.quizlet.quizletandroid.ui.studymodes.testmode.models.k) xVar;
                            testStudyModeActivity.b0();
                            AbstractC1136h0 supportFragmentManager5 = testStudyModeActivity.getSupportFragmentManager();
                            String str5 = LearnPaywallFragment.h;
                            if (supportFragmentManager5.E(str5) == null) {
                                ConstraintLayout testToolbar2 = ((C4606j) testStudyModeActivity.K()).g;
                                Intrinsics.checkNotNullExpressionValue(testToolbar2, "testToolbar");
                                testToolbar2.setVisibility(8);
                                ((com.quizlet.quizletandroid.ui.learnpaywall.k) testStudyModeActivity.t.getValue()).C(kVar2.a, kVar2.b, kVar2.c, kVar2.d);
                                LearnPaywallFragment learnPaywallFragment = new LearnPaywallFragment();
                                AbstractC1136h0 supportFragmentManager6 = testStudyModeActivity.getSupportFragmentManager();
                                supportFragmentManager6.getClass();
                                C1121a c1121a3 = new C1121a(supportFragmentManager6);
                                c1121a3.m(0, 0);
                                c1121a3.l(R.id.fragment_container, learnPaywallFragment, str5);
                                c1121a3.g();
                            }
                        } else {
                            if (!(xVar instanceof com.quizlet.quizletandroid.ui.studymodes.testmode.models.g)) {
                                throw new NoWhenBranchMatchedException();
                            }
                            testStudyModeActivity.b0();
                            TestStudyModeResultsLoadingFragment testStudyModeResultsLoadingFragment = new TestStudyModeResultsLoadingFragment();
                            AbstractC1136h0 supportFragmentManager7 = testStudyModeActivity.getSupportFragmentManager();
                            supportFragmentManager7.getClass();
                            C1121a c1121a4 = new C1121a(supportFragmentManager7);
                            c1121a4.m(0, 0);
                            c1121a4.l(R.id.fragment_container, testStudyModeResultsLoadingFragment, TestStudyModeResultsLoadingFragment.f);
                            c1121a4.g();
                        }
                        return Unit.a;
                    case 2:
                        com.quizlet.quizletandroid.ui.studymodes.testmode.models.v vVar = (com.quizlet.quizletandroid.ui.studymodes.testmode.models.v) obj;
                        String str6 = TestStudyModeActivity.v;
                        boolean z = vVar instanceof com.quizlet.quizletandroid.ui.studymodes.testmode.models.d;
                        TestStudyModeActivity context = this.b;
                        if (z) {
                            com.quizlet.quizletandroid.ui.studymodes.testmode.models.d dVar = (com.quizlet.quizletandroid.ui.studymodes.testmode.models.d) vVar;
                            String str7 = LearningAssistantActivity.D;
                            dVar.getClass();
                            Intent intentB = AbstractC3675m6.b(context, 0, dVar.a, dVar.c, dVar.b, dVar.d, 0, dVar.f, dVar.e, dVar.g);
                            context.finish();
                            context.startActivityForResult(intentB, 205);
                        } else if (vVar instanceof com.quizlet.quizletandroid.ui.studymodes.testmode.models.c) {
                            com.quizlet.quizletandroid.ui.studymodes.testmode.models.c cVar = (com.quizlet.quizletandroid.ui.studymodes.testmode.models.c) vVar;
                            int i8 = cVar.a;
                            String str8 = cVar.d;
                            com.quizlet.features.infra.basestudy.data.models.r rVar = new com.quizlet.features.infra.basestudy.data.models.r(i8, cVar.c, cVar.b, str8, null, cVar.e);
                            String str9 = FlashcardsActivity.j;
                            Intent intentC = AbstractC3110c0.c(context, rVar);
                            context.finish();
                            context.startActivityForResult(intentC, 204);
                        } else if (Intrinsics.b(vVar, com.quizlet.quizletandroid.ui.studymodes.testmode.models.e.a)) {
                            String str10 = UpgradeActivity.v;
                            Intent intentI = AbstractC3242q6.i(context, "test_toast", com.quizlet.features.infra.models.upgrade.a.t);
                            androidx.activity.result.b bVar2 = context.u;
                            if (bVar2 == null) {
                                Intrinsics.m("meteringToastUpgradeResultLauncher");
                                throw null;
                            }
                            bVar2.a(intentI);
                        } else {
                            if (!Intrinsics.b(vVar, com.quizlet.quizletandroid.ui.studymodes.testmode.models.j.a)) {
                                throw new NoWhenBranchMatchedException();
                            }
                            com.facebook.internal.K k = new com.facebook.internal.K(context, 5);
                            com.quizlet.explanations.questiondetail.ui.d dVar2 = new com.quizlet.explanations.questiondetail.ui.d(context, 4);
                            Intrinsics.checkNotNullParameter(context, "context");
                            String message = context.getString(R.string.set_page_feature_offline_blocked_description);
                            Intrinsics.checkNotNullExpressionValue(message, "getString(...)");
                            Intrinsics.checkNotNullParameter(message, "message");
                            String title = context.getString(R.string.set_page_feature_offline_blocked_title);
                            Intrinsics.checkNotNullExpressionValue(title, "getString(...)");
                            Intrinsics.checkNotNullParameter(title, "title");
                            String text = context.getString(R.string.got_it);
                            Intrinsics.checkNotNullExpressionValue(text, "getString(...)");
                            Intrinsics.checkNotNullParameter(text, "text");
                            i iVar = new i(new QAlertDialogFragment.DialogData(message, title, text, null, true, null), dVar2, null, k);
                            String str11 = QAlertDialogFragment.t;
                            h.a(iVar).O(context.getSupportFragmentManager(), QAlertDialogFragment.t);
                        }
                        return Unit.a;
                    case 3:
                        com.quizlet.quizletandroid.ui.studymodes.testmode.models.a aVar = (com.quizlet.quizletandroid.ui.studymodes.testmode.models.a) obj;
                        String str12 = TestStudyModeActivity.v;
                        if (Intrinsics.b(aVar, com.quizlet.quizletandroid.ui.studymodes.testmode.models.f.a)) {
                            e.a aVar2 = new e.a(testStudyModeActivity);
                            aVar2.d = testStudyModeActivity.getResources().getString(R.string.test_mode_start_test_failed_title);
                            aVar2.e = testStudyModeActivity.getResources().getString(R.string.test_mode_start_test_failed_message);
                            aVar2.i = testStudyModeActivity.getResources().getString(R.string.test_mode_start_test_failed_ok);
                            aVar2.j = null;
                            aVar2.g();
                        } else {
                            if (!Intrinsics.b(aVar, com.quizlet.quizletandroid.ui.studymodes.testmode.models.f.b)) {
                                throw new NoWhenBranchMatchedException();
                            }
                            e.a aVar3 = new e.a(testStudyModeActivity);
                            aVar3.c(R.string.test_mode_exit_confirmation);
                            aVar3.e(R.string.yes_dialog_button, new b(testStudyModeActivity));
                            aVar3.d(R.string.cancel_dialog_button, new com.quizlet.quizletandroid.ui.setcreation.imageupload.a(i42));
                            aVar3.b = false;
                            aVar3.g();
                        }
                        return Unit.a;
                    case 4:
                        String str13 = TestStudyModeActivity.v;
                        j jVar2 = (j) testStudyModeActivity.s.getValue();
                        long j = ((w) obj).a;
                        A1 studyModeType = A1.TEST;
                        k kVar3 = (k) jVar2;
                        kVar3.getClass();
                        Intrinsics.checkNotNullParameter(studyModeType, "studyModeType");
                        kVar3.c.a(j, studyModeType);
                        return Unit.a;
                    case 5:
                        String str14 = TestStudyModeActivity.v;
                        if (((Boolean) obj).booleanValue()) {
                            testStudyModeActivity.setResult(115);
                        }
                        testStudyModeActivity.finish();
                        return Unit.a;
                    default:
                        String str15 = TestStudyModeActivity.v;
                        G gC0 = testStudyModeActivity.c0();
                        int i9 = gC0.B + 1;
                        if (i9 >= gC0.e.a.size()) {
                            TestStudyModeConfig testStudyModeConfig = gC0.E;
                            if (testStudyModeConfig == null) {
                                throw new IllegalArgumentException("Required value was null.");
                            }
                            DBSession dBSession = gC0.K;
                            Intrinsics.d(dBSession);
                            E.A(p0.j(gC0), null, null, new com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.y(testStudyModeConfig, gC0, dBSession, null), 3);
                            gC0.G = false;
                            gC0.K = null;
                        } else {
                            gC0.J(i9);
                        }
                        return Unit.a;
                }
            }
        }));
        c0().x.f(this, new com.quizlet.explanations.feedback.ui.fragments.c(25, new Function1(this) { // from class: com.quizlet.quizletandroid.ui.studymodes.testmode.activities.a
            public final /* synthetic */ TestStudyModeActivity b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object obj) {
                int i42 = 3;
                TestStudyModeActivity testStudyModeActivity = this.b;
                switch (i) {
                    case 0:
                        com.quizlet.upgrade.util.a it2 = (com.quizlet.upgrade.util.a) obj;
                        String str = TestStudyModeActivity.v;
                        Intrinsics.checkNotNullParameter(it2, "it");
                        if (it2.a) {
                            testStudyModeActivity.d0(it2.c, false);
                        }
                        return Unit.a;
                    case 1:
                        x xVar = (x) obj;
                        String str2 = TestStudyModeActivity.v;
                        if (xVar instanceof s) {
                            s sVar = (s) xVar;
                            String str3 = TestModeStartFragment.l;
                            StudyEventLogData studyEventLogData = sVar.a;
                            Intrinsics.checkNotNullParameter(studyEventLogData, "studyEventLogData");
                            InterfaceC4176w0 meteredEvent = sVar.b;
                            Intrinsics.checkNotNullParameter(meteredEvent, "meteredEvent");
                            TestModeStartFragment testModeStartFragment = new TestModeStartFragment();
                            Bundle bundle2 = new Bundle();
                            bundle2.putParcelable("arg_study_event_log_data", studyEventLogData);
                            bundle2.putSerializable("arg_metered_event", meteredEvent);
                            testModeStartFragment.setArguments(bundle2);
                            AbstractC1136h0 supportFragmentManager = testStudyModeActivity.getSupportFragmentManager();
                            C1121a c1121aB = B.b(supportFragmentManager, supportFragmentManager);
                            c1121aB.l(R.id.fragment_container, testModeStartFragment, TestModeStartFragment.l);
                            c1121aB.g();
                        } else if (xVar instanceof q) {
                            q qVar = (q) xVar;
                            j jVar = (j) testStudyModeActivity.s.getValue();
                            ShowQuestion data = qVar.d;
                            k kVar = (k) jVar;
                            kVar.getClass();
                            Intrinsics.checkNotNullParameter(data, "data");
                            kVar.d.j(data);
                            testStudyModeActivity.setTitle((CharSequence) null);
                            int i52 = qVar.a;
                            int i62 = i52 + 1;
                            ConstraintLayout testToolbar = ((C4606j) testStudyModeActivity.K()).g;
                            Intrinsics.checkNotNullExpressionValue(testToolbar, "testToolbar");
                            testToolbar.setVisibility(0);
                            ((C4606j) testStudyModeActivity.K()).e.setProgress(i52);
                            QProgressBar qProgressBar = ((C4606j) testStudyModeActivity.K()).e;
                            int i7 = qVar.b;
                            qProgressBar.setMax(i7);
                            C4606j c4606j2 = (C4606j) testStudyModeActivity.K();
                            c4606j2.f.setText(testStudyModeActivity.getString(R.string.test_new_progress, String.valueOf(i62), String.valueOf(i7)));
                            AbstractC1136h0 supportFragmentManager2 = testStudyModeActivity.getSupportFragmentManager();
                            String str4 = QuestionCoordinatorFragment.k;
                            if (supportFragmentManager2.E(str4) == null) {
                                AbstractC1136h0 supportFragmentManager3 = testStudyModeActivity.getSupportFragmentManager();
                                supportFragmentManager3.getClass();
                                C1121a c1121a = new C1121a(supportFragmentManager3);
                                c1121a.m(0, 0);
                                c1121a.l(R.id.fragment_container, new QuestionCoordinatorFragment(), str4);
                                c1121a.g();
                            }
                            LinearLayout testModeParentLayout = ((C4606j) testStudyModeActivity.K()).d;
                            Intrinsics.checkNotNullExpressionValue(testModeParentLayout, "testModeParentLayout");
                            com.bumptech.glide.c.C(testModeParentLayout, qVar.c);
                        } else if (xVar instanceof r) {
                            ((C4606j) testStudyModeActivity.K()).g.setVisibility(0);
                            testStudyModeActivity.b0();
                            if (testStudyModeActivity.getSupportFragmentManager().E("TestModeResultsFragment") == null) {
                                TestModeResultsFragment testModeResultsFragment = new TestModeResultsFragment();
                                AbstractC1136h0 supportFragmentManager4 = testStudyModeActivity.getSupportFragmentManager();
                                supportFragmentManager4.getClass();
                                C1121a c1121a2 = new C1121a(supportFragmentManager4);
                                c1121a2.m(0, 0);
                                c1121a2.l(R.id.fragment_container, testModeResultsFragment, "TestModeResultsFragment");
                                c1121a2.g();
                            }
                        } else if (xVar instanceof com.quizlet.quizletandroid.ui.studymodes.testmode.models.k) {
                            com.quizlet.quizletandroid.ui.studymodes.testmode.models.k kVar2 = (com.quizlet.quizletandroid.ui.studymodes.testmode.models.k) xVar;
                            testStudyModeActivity.b0();
                            AbstractC1136h0 supportFragmentManager5 = testStudyModeActivity.getSupportFragmentManager();
                            String str5 = LearnPaywallFragment.h;
                            if (supportFragmentManager5.E(str5) == null) {
                                ConstraintLayout testToolbar2 = ((C4606j) testStudyModeActivity.K()).g;
                                Intrinsics.checkNotNullExpressionValue(testToolbar2, "testToolbar");
                                testToolbar2.setVisibility(8);
                                ((com.quizlet.quizletandroid.ui.learnpaywall.k) testStudyModeActivity.t.getValue()).C(kVar2.a, kVar2.b, kVar2.c, kVar2.d);
                                LearnPaywallFragment learnPaywallFragment = new LearnPaywallFragment();
                                AbstractC1136h0 supportFragmentManager6 = testStudyModeActivity.getSupportFragmentManager();
                                supportFragmentManager6.getClass();
                                C1121a c1121a3 = new C1121a(supportFragmentManager6);
                                c1121a3.m(0, 0);
                                c1121a3.l(R.id.fragment_container, learnPaywallFragment, str5);
                                c1121a3.g();
                            }
                        } else {
                            if (!(xVar instanceof com.quizlet.quizletandroid.ui.studymodes.testmode.models.g)) {
                                throw new NoWhenBranchMatchedException();
                            }
                            testStudyModeActivity.b0();
                            TestStudyModeResultsLoadingFragment testStudyModeResultsLoadingFragment = new TestStudyModeResultsLoadingFragment();
                            AbstractC1136h0 supportFragmentManager7 = testStudyModeActivity.getSupportFragmentManager();
                            supportFragmentManager7.getClass();
                            C1121a c1121a4 = new C1121a(supportFragmentManager7);
                            c1121a4.m(0, 0);
                            c1121a4.l(R.id.fragment_container, testStudyModeResultsLoadingFragment, TestStudyModeResultsLoadingFragment.f);
                            c1121a4.g();
                        }
                        return Unit.a;
                    case 2:
                        com.quizlet.quizletandroid.ui.studymodes.testmode.models.v vVar = (com.quizlet.quizletandroid.ui.studymodes.testmode.models.v) obj;
                        String str6 = TestStudyModeActivity.v;
                        boolean z = vVar instanceof com.quizlet.quizletandroid.ui.studymodes.testmode.models.d;
                        TestStudyModeActivity context = this.b;
                        if (z) {
                            com.quizlet.quizletandroid.ui.studymodes.testmode.models.d dVar = (com.quizlet.quizletandroid.ui.studymodes.testmode.models.d) vVar;
                            String str7 = LearningAssistantActivity.D;
                            dVar.getClass();
                            Intent intentB = AbstractC3675m6.b(context, 0, dVar.a, dVar.c, dVar.b, dVar.d, 0, dVar.f, dVar.e, dVar.g);
                            context.finish();
                            context.startActivityForResult(intentB, 205);
                        } else if (vVar instanceof com.quizlet.quizletandroid.ui.studymodes.testmode.models.c) {
                            com.quizlet.quizletandroid.ui.studymodes.testmode.models.c cVar = (com.quizlet.quizletandroid.ui.studymodes.testmode.models.c) vVar;
                            int i8 = cVar.a;
                            String str8 = cVar.d;
                            com.quizlet.features.infra.basestudy.data.models.r rVar = new com.quizlet.features.infra.basestudy.data.models.r(i8, cVar.c, cVar.b, str8, null, cVar.e);
                            String str9 = FlashcardsActivity.j;
                            Intent intentC = AbstractC3110c0.c(context, rVar);
                            context.finish();
                            context.startActivityForResult(intentC, 204);
                        } else if (Intrinsics.b(vVar, com.quizlet.quizletandroid.ui.studymodes.testmode.models.e.a)) {
                            String str10 = UpgradeActivity.v;
                            Intent intentI = AbstractC3242q6.i(context, "test_toast", com.quizlet.features.infra.models.upgrade.a.t);
                            androidx.activity.result.b bVar2 = context.u;
                            if (bVar2 == null) {
                                Intrinsics.m("meteringToastUpgradeResultLauncher");
                                throw null;
                            }
                            bVar2.a(intentI);
                        } else {
                            if (!Intrinsics.b(vVar, com.quizlet.quizletandroid.ui.studymodes.testmode.models.j.a)) {
                                throw new NoWhenBranchMatchedException();
                            }
                            com.facebook.internal.K k = new com.facebook.internal.K(context, 5);
                            com.quizlet.explanations.questiondetail.ui.d dVar2 = new com.quizlet.explanations.questiondetail.ui.d(context, 4);
                            Intrinsics.checkNotNullParameter(context, "context");
                            String message = context.getString(R.string.set_page_feature_offline_blocked_description);
                            Intrinsics.checkNotNullExpressionValue(message, "getString(...)");
                            Intrinsics.checkNotNullParameter(message, "message");
                            String title = context.getString(R.string.set_page_feature_offline_blocked_title);
                            Intrinsics.checkNotNullExpressionValue(title, "getString(...)");
                            Intrinsics.checkNotNullParameter(title, "title");
                            String text = context.getString(R.string.got_it);
                            Intrinsics.checkNotNullExpressionValue(text, "getString(...)");
                            Intrinsics.checkNotNullParameter(text, "text");
                            i iVar = new i(new QAlertDialogFragment.DialogData(message, title, text, null, true, null), dVar2, null, k);
                            String str11 = QAlertDialogFragment.t;
                            h.a(iVar).O(context.getSupportFragmentManager(), QAlertDialogFragment.t);
                        }
                        return Unit.a;
                    case 3:
                        com.quizlet.quizletandroid.ui.studymodes.testmode.models.a aVar = (com.quizlet.quizletandroid.ui.studymodes.testmode.models.a) obj;
                        String str12 = TestStudyModeActivity.v;
                        if (Intrinsics.b(aVar, com.quizlet.quizletandroid.ui.studymodes.testmode.models.f.a)) {
                            e.a aVar2 = new e.a(testStudyModeActivity);
                            aVar2.d = testStudyModeActivity.getResources().getString(R.string.test_mode_start_test_failed_title);
                            aVar2.e = testStudyModeActivity.getResources().getString(R.string.test_mode_start_test_failed_message);
                            aVar2.i = testStudyModeActivity.getResources().getString(R.string.test_mode_start_test_failed_ok);
                            aVar2.j = null;
                            aVar2.g();
                        } else {
                            if (!Intrinsics.b(aVar, com.quizlet.quizletandroid.ui.studymodes.testmode.models.f.b)) {
                                throw new NoWhenBranchMatchedException();
                            }
                            e.a aVar3 = new e.a(testStudyModeActivity);
                            aVar3.c(R.string.test_mode_exit_confirmation);
                            aVar3.e(R.string.yes_dialog_button, new b(testStudyModeActivity));
                            aVar3.d(R.string.cancel_dialog_button, new com.quizlet.quizletandroid.ui.setcreation.imageupload.a(i42));
                            aVar3.b = false;
                            aVar3.g();
                        }
                        return Unit.a;
                    case 4:
                        String str13 = TestStudyModeActivity.v;
                        j jVar2 = (j) testStudyModeActivity.s.getValue();
                        long j = ((w) obj).a;
                        A1 studyModeType = A1.TEST;
                        k kVar3 = (k) jVar2;
                        kVar3.getClass();
                        Intrinsics.checkNotNullParameter(studyModeType, "studyModeType");
                        kVar3.c.a(j, studyModeType);
                        return Unit.a;
                    case 5:
                        String str14 = TestStudyModeActivity.v;
                        if (((Boolean) obj).booleanValue()) {
                            testStudyModeActivity.setResult(115);
                        }
                        testStudyModeActivity.finish();
                        return Unit.a;
                    default:
                        String str15 = TestStudyModeActivity.v;
                        G gC0 = testStudyModeActivity.c0();
                        int i9 = gC0.B + 1;
                        if (i9 >= gC0.e.a.size()) {
                            TestStudyModeConfig testStudyModeConfig = gC0.E;
                            if (testStudyModeConfig == null) {
                                throw new IllegalArgumentException("Required value was null.");
                            }
                            DBSession dBSession = gC0.K;
                            Intrinsics.d(dBSession);
                            E.A(p0.j(gC0), null, null, new com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.y(testStudyModeConfig, gC0, dBSession, null), 3);
                            gC0.G = false;
                            gC0.K = null;
                        } else {
                            gC0.J(i9);
                        }
                        return Unit.a;
                }
            }
        }));
        final int i7 = 5;
        c0().u.f(this, new com.quizlet.explanations.feedback.ui.fragments.c(25, new Function1(this) { // from class: com.quizlet.quizletandroid.ui.studymodes.testmode.activities.a
            public final /* synthetic */ TestStudyModeActivity b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object obj) {
                int i42 = 3;
                TestStudyModeActivity testStudyModeActivity = this.b;
                switch (i7) {
                    case 0:
                        com.quizlet.upgrade.util.a it2 = (com.quizlet.upgrade.util.a) obj;
                        String str = TestStudyModeActivity.v;
                        Intrinsics.checkNotNullParameter(it2, "it");
                        if (it2.a) {
                            testStudyModeActivity.d0(it2.c, false);
                        }
                        return Unit.a;
                    case 1:
                        x xVar = (x) obj;
                        String str2 = TestStudyModeActivity.v;
                        if (xVar instanceof s) {
                            s sVar = (s) xVar;
                            String str3 = TestModeStartFragment.l;
                            StudyEventLogData studyEventLogData = sVar.a;
                            Intrinsics.checkNotNullParameter(studyEventLogData, "studyEventLogData");
                            InterfaceC4176w0 meteredEvent = sVar.b;
                            Intrinsics.checkNotNullParameter(meteredEvent, "meteredEvent");
                            TestModeStartFragment testModeStartFragment = new TestModeStartFragment();
                            Bundle bundle2 = new Bundle();
                            bundle2.putParcelable("arg_study_event_log_data", studyEventLogData);
                            bundle2.putSerializable("arg_metered_event", meteredEvent);
                            testModeStartFragment.setArguments(bundle2);
                            AbstractC1136h0 supportFragmentManager = testStudyModeActivity.getSupportFragmentManager();
                            C1121a c1121aB = B.b(supportFragmentManager, supportFragmentManager);
                            c1121aB.l(R.id.fragment_container, testModeStartFragment, TestModeStartFragment.l);
                            c1121aB.g();
                        } else if (xVar instanceof q) {
                            q qVar = (q) xVar;
                            j jVar = (j) testStudyModeActivity.s.getValue();
                            ShowQuestion data = qVar.d;
                            k kVar = (k) jVar;
                            kVar.getClass();
                            Intrinsics.checkNotNullParameter(data, "data");
                            kVar.d.j(data);
                            testStudyModeActivity.setTitle((CharSequence) null);
                            int i52 = qVar.a;
                            int i62 = i52 + 1;
                            ConstraintLayout testToolbar = ((C4606j) testStudyModeActivity.K()).g;
                            Intrinsics.checkNotNullExpressionValue(testToolbar, "testToolbar");
                            testToolbar.setVisibility(0);
                            ((C4606j) testStudyModeActivity.K()).e.setProgress(i52);
                            QProgressBar qProgressBar = ((C4606j) testStudyModeActivity.K()).e;
                            int i72 = qVar.b;
                            qProgressBar.setMax(i72);
                            C4606j c4606j2 = (C4606j) testStudyModeActivity.K();
                            c4606j2.f.setText(testStudyModeActivity.getString(R.string.test_new_progress, String.valueOf(i62), String.valueOf(i72)));
                            AbstractC1136h0 supportFragmentManager2 = testStudyModeActivity.getSupportFragmentManager();
                            String str4 = QuestionCoordinatorFragment.k;
                            if (supportFragmentManager2.E(str4) == null) {
                                AbstractC1136h0 supportFragmentManager3 = testStudyModeActivity.getSupportFragmentManager();
                                supportFragmentManager3.getClass();
                                C1121a c1121a = new C1121a(supportFragmentManager3);
                                c1121a.m(0, 0);
                                c1121a.l(R.id.fragment_container, new QuestionCoordinatorFragment(), str4);
                                c1121a.g();
                            }
                            LinearLayout testModeParentLayout = ((C4606j) testStudyModeActivity.K()).d;
                            Intrinsics.checkNotNullExpressionValue(testModeParentLayout, "testModeParentLayout");
                            com.bumptech.glide.c.C(testModeParentLayout, qVar.c);
                        } else if (xVar instanceof r) {
                            ((C4606j) testStudyModeActivity.K()).g.setVisibility(0);
                            testStudyModeActivity.b0();
                            if (testStudyModeActivity.getSupportFragmentManager().E("TestModeResultsFragment") == null) {
                                TestModeResultsFragment testModeResultsFragment = new TestModeResultsFragment();
                                AbstractC1136h0 supportFragmentManager4 = testStudyModeActivity.getSupportFragmentManager();
                                supportFragmentManager4.getClass();
                                C1121a c1121a2 = new C1121a(supportFragmentManager4);
                                c1121a2.m(0, 0);
                                c1121a2.l(R.id.fragment_container, testModeResultsFragment, "TestModeResultsFragment");
                                c1121a2.g();
                            }
                        } else if (xVar instanceof com.quizlet.quizletandroid.ui.studymodes.testmode.models.k) {
                            com.quizlet.quizletandroid.ui.studymodes.testmode.models.k kVar2 = (com.quizlet.quizletandroid.ui.studymodes.testmode.models.k) xVar;
                            testStudyModeActivity.b0();
                            AbstractC1136h0 supportFragmentManager5 = testStudyModeActivity.getSupportFragmentManager();
                            String str5 = LearnPaywallFragment.h;
                            if (supportFragmentManager5.E(str5) == null) {
                                ConstraintLayout testToolbar2 = ((C4606j) testStudyModeActivity.K()).g;
                                Intrinsics.checkNotNullExpressionValue(testToolbar2, "testToolbar");
                                testToolbar2.setVisibility(8);
                                ((com.quizlet.quizletandroid.ui.learnpaywall.k) testStudyModeActivity.t.getValue()).C(kVar2.a, kVar2.b, kVar2.c, kVar2.d);
                                LearnPaywallFragment learnPaywallFragment = new LearnPaywallFragment();
                                AbstractC1136h0 supportFragmentManager6 = testStudyModeActivity.getSupportFragmentManager();
                                supportFragmentManager6.getClass();
                                C1121a c1121a3 = new C1121a(supportFragmentManager6);
                                c1121a3.m(0, 0);
                                c1121a3.l(R.id.fragment_container, learnPaywallFragment, str5);
                                c1121a3.g();
                            }
                        } else {
                            if (!(xVar instanceof com.quizlet.quizletandroid.ui.studymodes.testmode.models.g)) {
                                throw new NoWhenBranchMatchedException();
                            }
                            testStudyModeActivity.b0();
                            TestStudyModeResultsLoadingFragment testStudyModeResultsLoadingFragment = new TestStudyModeResultsLoadingFragment();
                            AbstractC1136h0 supportFragmentManager7 = testStudyModeActivity.getSupportFragmentManager();
                            supportFragmentManager7.getClass();
                            C1121a c1121a4 = new C1121a(supportFragmentManager7);
                            c1121a4.m(0, 0);
                            c1121a4.l(R.id.fragment_container, testStudyModeResultsLoadingFragment, TestStudyModeResultsLoadingFragment.f);
                            c1121a4.g();
                        }
                        return Unit.a;
                    case 2:
                        com.quizlet.quizletandroid.ui.studymodes.testmode.models.v vVar = (com.quizlet.quizletandroid.ui.studymodes.testmode.models.v) obj;
                        String str6 = TestStudyModeActivity.v;
                        boolean z = vVar instanceof com.quizlet.quizletandroid.ui.studymodes.testmode.models.d;
                        TestStudyModeActivity context = this.b;
                        if (z) {
                            com.quizlet.quizletandroid.ui.studymodes.testmode.models.d dVar = (com.quizlet.quizletandroid.ui.studymodes.testmode.models.d) vVar;
                            String str7 = LearningAssistantActivity.D;
                            dVar.getClass();
                            Intent intentB = AbstractC3675m6.b(context, 0, dVar.a, dVar.c, dVar.b, dVar.d, 0, dVar.f, dVar.e, dVar.g);
                            context.finish();
                            context.startActivityForResult(intentB, 205);
                        } else if (vVar instanceof com.quizlet.quizletandroid.ui.studymodes.testmode.models.c) {
                            com.quizlet.quizletandroid.ui.studymodes.testmode.models.c cVar = (com.quizlet.quizletandroid.ui.studymodes.testmode.models.c) vVar;
                            int i8 = cVar.a;
                            String str8 = cVar.d;
                            com.quizlet.features.infra.basestudy.data.models.r rVar = new com.quizlet.features.infra.basestudy.data.models.r(i8, cVar.c, cVar.b, str8, null, cVar.e);
                            String str9 = FlashcardsActivity.j;
                            Intent intentC = AbstractC3110c0.c(context, rVar);
                            context.finish();
                            context.startActivityForResult(intentC, 204);
                        } else if (Intrinsics.b(vVar, com.quizlet.quizletandroid.ui.studymodes.testmode.models.e.a)) {
                            String str10 = UpgradeActivity.v;
                            Intent intentI = AbstractC3242q6.i(context, "test_toast", com.quizlet.features.infra.models.upgrade.a.t);
                            androidx.activity.result.b bVar2 = context.u;
                            if (bVar2 == null) {
                                Intrinsics.m("meteringToastUpgradeResultLauncher");
                                throw null;
                            }
                            bVar2.a(intentI);
                        } else {
                            if (!Intrinsics.b(vVar, com.quizlet.quizletandroid.ui.studymodes.testmode.models.j.a)) {
                                throw new NoWhenBranchMatchedException();
                            }
                            com.facebook.internal.K k = new com.facebook.internal.K(context, 5);
                            com.quizlet.explanations.questiondetail.ui.d dVar2 = new com.quizlet.explanations.questiondetail.ui.d(context, 4);
                            Intrinsics.checkNotNullParameter(context, "context");
                            String message = context.getString(R.string.set_page_feature_offline_blocked_description);
                            Intrinsics.checkNotNullExpressionValue(message, "getString(...)");
                            Intrinsics.checkNotNullParameter(message, "message");
                            String title = context.getString(R.string.set_page_feature_offline_blocked_title);
                            Intrinsics.checkNotNullExpressionValue(title, "getString(...)");
                            Intrinsics.checkNotNullParameter(title, "title");
                            String text = context.getString(R.string.got_it);
                            Intrinsics.checkNotNullExpressionValue(text, "getString(...)");
                            Intrinsics.checkNotNullParameter(text, "text");
                            i iVar = new i(new QAlertDialogFragment.DialogData(message, title, text, null, true, null), dVar2, null, k);
                            String str11 = QAlertDialogFragment.t;
                            h.a(iVar).O(context.getSupportFragmentManager(), QAlertDialogFragment.t);
                        }
                        return Unit.a;
                    case 3:
                        com.quizlet.quizletandroid.ui.studymodes.testmode.models.a aVar = (com.quizlet.quizletandroid.ui.studymodes.testmode.models.a) obj;
                        String str12 = TestStudyModeActivity.v;
                        if (Intrinsics.b(aVar, com.quizlet.quizletandroid.ui.studymodes.testmode.models.f.a)) {
                            e.a aVar2 = new e.a(testStudyModeActivity);
                            aVar2.d = testStudyModeActivity.getResources().getString(R.string.test_mode_start_test_failed_title);
                            aVar2.e = testStudyModeActivity.getResources().getString(R.string.test_mode_start_test_failed_message);
                            aVar2.i = testStudyModeActivity.getResources().getString(R.string.test_mode_start_test_failed_ok);
                            aVar2.j = null;
                            aVar2.g();
                        } else {
                            if (!Intrinsics.b(aVar, com.quizlet.quizletandroid.ui.studymodes.testmode.models.f.b)) {
                                throw new NoWhenBranchMatchedException();
                            }
                            e.a aVar3 = new e.a(testStudyModeActivity);
                            aVar3.c(R.string.test_mode_exit_confirmation);
                            aVar3.e(R.string.yes_dialog_button, new b(testStudyModeActivity));
                            aVar3.d(R.string.cancel_dialog_button, new com.quizlet.quizletandroid.ui.setcreation.imageupload.a(i42));
                            aVar3.b = false;
                            aVar3.g();
                        }
                        return Unit.a;
                    case 4:
                        String str13 = TestStudyModeActivity.v;
                        j jVar2 = (j) testStudyModeActivity.s.getValue();
                        long j = ((w) obj).a;
                        A1 studyModeType = A1.TEST;
                        k kVar3 = (k) jVar2;
                        kVar3.getClass();
                        Intrinsics.checkNotNullParameter(studyModeType, "studyModeType");
                        kVar3.c.a(j, studyModeType);
                        return Unit.a;
                    case 5:
                        String str14 = TestStudyModeActivity.v;
                        if (((Boolean) obj).booleanValue()) {
                            testStudyModeActivity.setResult(115);
                        }
                        testStudyModeActivity.finish();
                        return Unit.a;
                    default:
                        String str15 = TestStudyModeActivity.v;
                        G gC0 = testStudyModeActivity.c0();
                        int i9 = gC0.B + 1;
                        if (i9 >= gC0.e.a.size()) {
                            TestStudyModeConfig testStudyModeConfig = gC0.E;
                            if (testStudyModeConfig == null) {
                                throw new IllegalArgumentException("Required value was null.");
                            }
                            DBSession dBSession = gC0.K;
                            Intrinsics.d(dBSession);
                            E.A(p0.j(gC0), null, null, new com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.y(testStudyModeConfig, gC0, dBSession, null), 3);
                            gC0.G = false;
                            gC0.K = null;
                        } else {
                            gC0.J(i9);
                        }
                        return Unit.a;
                }
            }
        }));
        E.A(p0.h(this), null, null, new e(this, null), 3);
        G gC0 = c0();
        Serializable serializableExtra = getIntent().getSerializableExtra("meteredEvent");
        Intrinsics.e(serializableExtra, "null cannot be cast to non-null type com.quizlet.data.model.MeteredEvent");
        InterfaceC4176w0 testMeteredEvent = (InterfaceC4176w0) serializableExtra;
        Serializable serializableExtra2 = getIntent().getSerializableExtra("learnMeteredEvent");
        Intrinsics.e(serializableExtra2, "null cannot be cast to non-null type com.quizlet.data.model.MeteredEvent");
        InterfaceC4176w0 learnMeteredEvent = (InterfaceC4176w0) serializableExtra2;
        boolean booleanExtra = getIntent().getBooleanExtra("isFromNotes", false);
        gC0.getClass();
        Intrinsics.checkNotNullParameter(testMeteredEvent, "testMeteredEvent");
        Intrinsics.checkNotNullParameter(learnMeteredEvent, "learnMeteredEvent");
        gC0.L = booleanExtra;
        InterfaceC4176w0 interfaceC4176w0 = gC0.J;
        if (interfaceC4176w0 == null || !interfaceC4176w0.equals(learnMeteredEvent)) {
            gC0.J = learnMeteredEvent;
        }
        InterfaceC4176w0 interfaceC4176w02 = gC0.I;
        if (interfaceC4176w02 == null || !interfaceC4176w02.equals(testMeteredEvent)) {
            gC0.I = testMeteredEvent;
            com.quizlet.features.infra.basestudy.manager.f fVar = gC0.D;
            io.reactivex.rxjava3.disposables.b bVarU = fVar.c().u(new com.quizlet.billing.manager.b(22, gC0, testMeteredEvent), io.reactivex.rxjava3.internal.functions.d.e, io.reactivex.rxjava3.internal.functions.d.c);
            Intrinsics.checkNotNullExpressionValue(bVarU, "subscribe(...)");
            Intrinsics.checkNotNullParameter(bVarU, "<this>");
            gC0.A(bVarU);
            fVar.m();
            gC0.v.j(testMeteredEvent);
            E.A(p0.j(gC0), null, null, new D(gC0, null), 3);
        }
        AbstractC3699p6.b(this, R.attr.SysColorCard);
        setTitle(w);
        C4606j c4606j2 = (C4606j) K();
        c4606j2.b.setOnClickListener(new com.quizlet.quizletandroid.ui.common.adapter.viewholder.h(this, 18));
    }

    @Override // com.quizlet.baseui.base.b, androidx.appcompat.app.AbstractActivityC0055k, androidx.fragment.app.I, android.app.Activity
    public final void onStart() {
        super.onStart();
        com.quizlet.features.infra.basestudy.manager.f.h(c0().D);
    }

    @Override // com.quizlet.baseui.base.b, androidx.appcompat.app.AbstractActivityC0055k, androidx.fragment.app.I, android.app.Activity
    public final void onStop() {
        com.quizlet.features.infra.basestudy.manager.f.i(c0().D);
        super.onStop();
    }
}

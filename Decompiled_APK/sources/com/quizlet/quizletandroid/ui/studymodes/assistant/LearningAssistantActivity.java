package com.quizlet.quizletandroid.ui.studymodes.assistant;

import android.content.Intent;
import android.os.Bundle;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import androidx.activity.result.ActivityResult;
import androidx.activity.v;
import androidx.compose.ui.platform.ComposeView;
import androidx.coordinatorlayout.widget.CoordinatorLayout;
import androidx.core.view.L;
import androidx.core.view.V;
import androidx.fragment.app.AbstractC1136h0;
import androidx.fragment.app.C1121a;
import androidx.lifecycle.p0;
import com.airbnb.lottie.LottieAnimationView;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.google.android.gms.internal.mlkit_vision_document_scanner.H6;
import com.quizlet.baseui.base.BaseFragment;
import com.quizlet.data.model.InterfaceC4176w0;
import com.quizlet.features.questiontypes.basequestion.data.ShowQuestion;
import com.quizlet.features.questiontypes.coordinator.QuestionCoordinatorFragment;
import com.quizlet.learn.settings.data.LearnSettingsResult;
import com.quizlet.learn.viewmodel.G;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.databinding.C4609m;
import com.quizlet.quizletandroid.ui.globalnav.composable.s;
import java.io.Serializable;
import java.util.WeakHashMap;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;
import kotlin.u;
import kotlinx.coroutines.E;

@Metadata
/* loaded from: classes3.dex */
public final class LearningAssistantActivity extends com.quizlet.ads.ui.activity.d {
    public static final String D;
    public androidx.activity.result.b A;
    public androidx.activity.result.b B;
    public androidx.activity.result.b C;
    public final u q;
    public final u r;
    public final u s;
    public final u t;
    public com.onetrust.otpublishers.headless.UI.viewmodel.c u;
    public final com.quizlet.data.repository.folderwithcreatorinclass.e v;
    public final com.quizlet.data.repository.folderwithcreatorinclass.e w;
    public final com.quizlet.data.repository.folderwithcreatorinclass.e x;
    public final com.quizlet.data.repository.folderwithcreatorinclass.e y;
    public final com.quizlet.data.repository.folderwithcreatorinclass.e z;

    static {
        Intrinsics.checkNotNullExpressionValue("LearningAssistantActivity", "getSimpleName(...)");
        D = "LearningAssistantActivity";
    }

    public LearningAssistantActivity() {
        super(9);
        this.q = kotlin.l.b(new e(this, 0));
        this.r = kotlin.l.b(new e(this, 1));
        this.s = kotlin.l.b(new e(this, 2));
        this.t = kotlin.l.b(new e(this, 3));
        this.v = new com.quizlet.data.repository.folderwithcreatorinclass.e(K.a(com.quizlet.features.questiontypes.basequestion.k.class), new m(this, 7), new m(this, 6), new m(this, 8));
        this.w = new com.quizlet.data.repository.folderwithcreatorinclass.e(K.a(G.class), new m(this, 10), new m(this, 9), new m(this, 11));
        this.x = new com.quizlet.data.repository.folderwithcreatorinclass.e(K.a(com.quizlet.quizletandroid.ui.learnpaywall.k.class), new m(this, 12), new e(this, 4), new m(this, 13));
        this.y = new com.quizlet.data.repository.folderwithcreatorinclass.e(K.a(com.quizlet.learn.viewmodel.i.class), new m(this, 1), new m(this, 0), new m(this, 2));
        this.z = new com.quizlet.data.repository.folderwithcreatorinclass.e(K.a(com.quizlet.quizletandroid.ui.studymodes.assistant.settings.viewmodel.i.class), new m(this, 4), new m(this, 3), new m(this, 5));
    }

    public static void f0(LearningAssistantActivity learningAssistantActivity, BaseFragment baseFragment, String str, boolean z) {
        AbstractC1136h0 supportFragmentManager = learningAssistantActivity.getSupportFragmentManager();
        supportFragmentManager.getClass();
        C1121a c1121a = new C1121a(supportFragmentManager);
        c1121a.m(0, 0);
        c1121a.l(R.id.fragment_question_container, baseFragment, str);
        Intrinsics.checkNotNullExpressionValue(c1121a, "replace(...)");
        if (z) {
            c1121a.h(true, true);
        } else {
            c1121a.g();
        }
    }

    @Override // com.quizlet.baseui.base.b
    public final String D() {
        return D;
    }

    @Override // com.quizlet.baseui.base.f
    public final androidx.viewbinding.a N() {
        View viewInflate = getLayoutInflater().inflate(R.layout.assistant_activity, (ViewGroup) null, false);
        int i = R.id.confetti_view;
        LottieAnimationView lottieAnimationView = (LottieAnimationView) AbstractC3375o2.c(R.id.confetti_view, viewInflate);
        if (lottieAnimationView != null) {
            i = R.id.coordinator_layout;
            if (((CoordinatorLayout) AbstractC3375o2.c(R.id.coordinator_layout, viewInflate)) != null) {
                i = R.id.fragment_question_container;
                FrameLayout frameLayout = (FrameLayout) AbstractC3375o2.c(R.id.fragment_question_container, viewInflate);
                if (frameLayout != null) {
                    i = R.id.learn_linear_layout;
                    LinearLayout linearLayout = (LinearLayout) AbstractC3375o2.c(R.id.learn_linear_layout, viewInflate);
                    if (linearLayout != null) {
                        i = R.id.learn_toolbar;
                        ComposeView composeView = (ComposeView) AbstractC3375o2.c(R.id.learn_toolbar, viewInflate);
                        if (composeView != null) {
                            i = R.id.loading_spinner;
                            ProgressBar progressBar = (ProgressBar) AbstractC3375o2.c(R.id.loading_spinner, viewInflate);
                            if (progressBar != null) {
                                i = R.id.onboarding_view;
                                ComposeView composeView2 = (ComposeView) AbstractC3375o2.c(R.id.onboarding_view, viewInflate);
                                if (composeView2 != null) {
                                    i = R.id.settings_view;
                                    ComposeView composeView3 = (ComposeView) AbstractC3375o2.c(R.id.settings_view, viewInflate);
                                    if (composeView3 != null) {
                                        C4609m c4609m = new C4609m((FrameLayout) viewInflate, lottieAnimationView, frameLayout, linearLayout, composeView, progressBar, composeView2, composeView3);
                                        Intrinsics.checkNotNullExpressionValue(c4609m, "inflate(...)");
                                        return c4609m;
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

    public final G b0() {
        return (G) this.w.getValue();
    }

    public final com.quizlet.learn.viewmodel.i c0() {
        return (com.quizlet.learn.viewmodel.i) this.y.getValue();
    }

    public final com.quizlet.features.questiontypes.basequestion.k d0() {
        return (com.quizlet.features.questiontypes.basequestion.k) this.v.getValue();
    }

    public final void e0(boolean z) {
        if (z) {
            Serializable serializableExtra = getIntent().getSerializableExtra("meteredEvent");
            Intrinsics.e(serializableExtra, "null cannot be cast to non-null type com.quizlet.data.model.MeteredEvent");
            Intent intent = new Intent(this, (Class<?>) LearningAssistantActivity.class);
            intent.putExtras(getIntent());
            intent.putExtra("meteredEvent", H6.c((InterfaceC4176w0) serializableExtra));
            startActivity(intent);
        }
        finish();
    }

    public final void g0(ShowQuestion data, int i) {
        com.quizlet.quizletandroid.util.d.a(this, getString(i));
        com.quizlet.features.questiontypes.basequestion.k kVarD0 = d0();
        kVarD0.getClass();
        Intrinsics.checkNotNullParameter(data, "data");
        kVarD0.d.j(data);
        AbstractC1136h0 supportFragmentManager = getSupportFragmentManager();
        String str = QuestionCoordinatorFragment.k;
        if (supportFragmentManager.E(str) != null) {
            return;
        }
        f0(this, new QuestionCoordinatorFragment(), str, false);
    }

    public final void h0(boolean z) {
        com.facebook.appevents.cloudbridge.c.c((ProgressBar) this.r.getValue(), !z);
        Object value = this.q.getValue();
        Intrinsics.checkNotNullExpressionValue(value, "getValue(...)");
        com.facebook.appevents.cloudbridge.c.c((View) value, z);
    }

    @Override // androidx.activity.s, android.app.Activity
    public final void onBackPressed() {
        b0().S();
    }

    @Override // com.quizlet.ads.ui.activity.d, com.quizlet.baseui.base.f, com.quizlet.baseui.base.b, androidx.fragment.app.I, androidx.activity.s, androidx.core.app.AbstractActivityC1021h, android.app.Activity
    public final void onCreate(Bundle bundle) {
        final int i = 0;
        final int i2 = 1;
        int i3 = 4;
        super.onCreate(bundle);
        v.b(this, null, 3);
        C4609m c4609m = (C4609m) K();
        com.quizlet.infra.legacysyncengine.tasks.parse.b bVar = new com.quizlet.infra.legacysyncengine.tasks.parse.b(this, 20);
        WeakHashMap weakHashMap = V.a;
        L.m(c4609m.a, bVar);
        b0().L.f(this, new com.quizlet.explanations.feedback.ui.fragments.c(19, new c(this, 6)));
        b0().W.f(this, new com.quizlet.explanations.feedback.ui.fragments.c(19, new c(this, i)));
        b0().X.f(this, new com.quizlet.explanations.feedback.ui.fragments.c(19, new s(1, d0(), com.quizlet.features.questiontypes.basequestion.k.class, "onAudioChanged", "onAudioChanged(Z)V", 0, 28)));
        b0().M.f(this, new com.quizlet.explanations.feedback.ui.fragments.c(19, new c(this, i2)));
        d0().f.f(this, new com.quizlet.explanations.feedback.ui.fragments.c(19, new c(this, 2)));
        d0().e.f(this, new com.quizlet.explanations.feedback.ui.fragments.c(19, new c(this, 3)));
        d0().g.f(this, new com.quizlet.explanations.feedback.ui.fragments.c(19, new c(this, i3)));
        E.A(p0.h(this), null, null, new i(this, null), 3);
        E.A(p0.h(this), null, null, new l(this, null), 3);
        setTitle("");
        h0(true);
        this.A = registerForActivityResult(new androidx.activity.result.contract.b(i3), new androidx.activity.result.a(this) { // from class: com.quizlet.quizletandroid.ui.studymodes.assistant.b
            public final /* synthetic */ LearningAssistantActivity b;

            {
                this.b = this;
            }

            @Override // androidx.activity.result.a
            public final void a(Object obj) {
                Intent intent;
                LearnSettingsResult learnSettingsResult;
                LearningAssistantActivity learningAssistantActivity = this.b;
                ActivityResult it2 = (ActivityResult) obj;
                switch (i) {
                    case 0:
                        String str = LearningAssistantActivity.D;
                        Intrinsics.checkNotNullParameter(it2, "it");
                        com.quizlet.learn.ads.h hVar = learningAssistantActivity.b0().B1;
                        hVar.getClass();
                        hVar.a(new com.quizlet.featuregate.growthbook.a(hVar, 22));
                        break;
                    default:
                        String str2 = LearningAssistantActivity.D;
                        Intrinsics.checkNotNullParameter(it2, "it");
                        if (it2.a == -1 && (intent = it2.b) != null && (learnSettingsResult = (LearnSettingsResult) androidx.core.content.c.e(intent, "result_learn_settings", LearnSettingsResult.class)) != null) {
                            learningAssistantActivity.b0().W(learnSettingsResult);
                            break;
                        }
                        break;
                }
            }
        });
        c onUpgradeFinished = new c(this, 5);
        Intrinsics.checkNotNullParameter(this, "activity");
        Intrinsics.checkNotNullParameter(onUpgradeFinished, "onUpgradeFinished");
        this.B = registerForActivityResult(new androidx.activity.result.contract.b(i3), new androidx.activity.compose.b(onUpgradeFinished, 9));
        this.C = registerForActivityResult(new androidx.activity.result.contract.b(i3), new androidx.activity.result.a(this) { // from class: com.quizlet.quizletandroid.ui.studymodes.assistant.b
            public final /* synthetic */ LearningAssistantActivity b;

            {
                this.b = this;
            }

            @Override // androidx.activity.result.a
            public final void a(Object obj) {
                Intent intent;
                LearnSettingsResult learnSettingsResult;
                LearningAssistantActivity learningAssistantActivity = this.b;
                ActivityResult it2 = (ActivityResult) obj;
                switch (i2) {
                    case 0:
                        String str = LearningAssistantActivity.D;
                        Intrinsics.checkNotNullParameter(it2, "it");
                        com.quizlet.learn.ads.h hVar = learningAssistantActivity.b0().B1;
                        hVar.getClass();
                        hVar.a(new com.quizlet.featuregate.growthbook.a(hVar, 22));
                        break;
                    default:
                        String str2 = LearningAssistantActivity.D;
                        Intrinsics.checkNotNullParameter(it2, "it");
                        if (it2.a == -1 && (intent = it2.b) != null && (learnSettingsResult = (LearnSettingsResult) androidx.core.content.c.e(intent, "result_learn_settings", LearnSettingsResult.class)) != null) {
                            learningAssistantActivity.b0().W(learnSettingsResult);
                            break;
                        }
                        break;
                }
            }
        });
        C4609m c4609m2 = (C4609m) K();
        c4609m2.e.setContent(new androidx.compose.runtime.internal.d(true, -2076425565, new com.quizlet.assembly.compose.cards.c(this, 29)));
    }

    @Override // com.quizlet.baseui.base.b, androidx.appcompat.app.AbstractActivityC0055k, androidx.fragment.app.I, android.app.Activity
    public final void onStart() {
        super.onStart();
        b0().Q();
    }

    @Override // com.quizlet.baseui.base.b, androidx.appcompat.app.AbstractActivityC0055k, androidx.fragment.app.I, android.app.Activity
    public final void onStop() {
        com.quizlet.features.infra.basestudy.manager.f.i(b0().Z);
        super.onStop();
    }
}

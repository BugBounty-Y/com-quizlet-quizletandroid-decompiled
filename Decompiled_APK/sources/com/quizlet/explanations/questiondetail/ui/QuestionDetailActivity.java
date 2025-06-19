package com.quizlet.explanations.questiondetail.ui;

import android.os.Bundle;
import android.view.View;
import android.view.ViewGroup;
import androidx.activity.v;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.fragment.app.AbstractC1136h0;
import androidx.fragment.app.C1121a;
import androidx.fragment.app.FragmentContainerView;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3188k6;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.quizlet.explanations.questiondetail.data.QuestionDetailSetUpState;
import com.quizlet.quizletandroid.R;
import kotlin.Metadata;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.l;
import kotlin.u;

@Metadata
/* loaded from: classes2.dex */
public final class QuestionDetailActivity extends com.quizlet.ads.ui.activity.d {
    public static final String t;
    public com.quizlet.shared.usecase.srs.a q;
    public final u r;
    public final u s;

    static {
        Intrinsics.checkNotNullExpressionValue("QuestionDetailActivity", "getSimpleName(...)");
        t = "QuestionDetailActivity";
    }

    public QuestionDetailActivity() {
        super(1);
        final int i = 0;
        this.r = l.b(new Function0(this) { // from class: com.quizlet.explanations.questiondetail.ui.a
            public final /* synthetic */ QuestionDetailActivity b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                QuestionDetailActivity questionDetailActivity = this.b;
                switch (i) {
                    case 0:
                        String str = QuestionDetailActivity.t;
                        return ((com.quizlet.explanations.databinding.a) questionDetailActivity.K()).b;
                    default:
                        String str2 = QuestionDetailActivity.t;
                        QuestionDetailSetUpState questionDetailSetUpState = (QuestionDetailSetUpState) questionDetailActivity.getIntent().getParcelableExtra("EXTRA_QUESTION_DETAIL_SET_UP_STATE");
                        if (questionDetailSetUpState != null) {
                            return questionDetailSetUpState;
                        }
                        throw new IllegalStateException("Missing required extra (EXTRA_QUESTION_DETAIL_SET_UP_STATE)");
                }
            }
        });
        final int i2 = 1;
        this.s = l.b(new Function0(this) { // from class: com.quizlet.explanations.questiondetail.ui.a
            public final /* synthetic */ QuestionDetailActivity b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                QuestionDetailActivity questionDetailActivity = this.b;
                switch (i2) {
                    case 0:
                        String str = QuestionDetailActivity.t;
                        return ((com.quizlet.explanations.databinding.a) questionDetailActivity.K()).b;
                    default:
                        String str2 = QuestionDetailActivity.t;
                        QuestionDetailSetUpState questionDetailSetUpState = (QuestionDetailSetUpState) questionDetailActivity.getIntent().getParcelableExtra("EXTRA_QUESTION_DETAIL_SET_UP_STATE");
                        if (questionDetailSetUpState != null) {
                            return questionDetailSetUpState;
                        }
                        throw new IllegalStateException("Missing required extra (EXTRA_QUESTION_DETAIL_SET_UP_STATE)");
                }
            }
        });
    }

    @Override // com.quizlet.baseui.base.b
    public final String D() {
        return t;
    }

    @Override // com.quizlet.baseui.base.f
    public final androidx.viewbinding.a N() {
        View viewInflate = getLayoutInflater().inflate(R.layout.activity_question_detail, (ViewGroup) null, false);
        FragmentContainerView fragmentContainerView = (FragmentContainerView) AbstractC3375o2.c(R.id.fragmentContainer, viewInflate);
        if (fragmentContainerView == null) {
            throw new NullPointerException("Missing required view with ID: ".concat(viewInflate.getResources().getResourceName(R.id.fragmentContainer)));
        }
        com.quizlet.explanations.databinding.a aVar = new com.quizlet.explanations.databinding.a((ConstraintLayout) viewInflate, fragmentContainerView);
        Intrinsics.checkNotNullExpressionValue(aVar, "inflate(...)");
        return aVar;
    }

    @Override // com.quizlet.ads.ui.activity.d, com.quizlet.baseui.base.f, com.quizlet.baseui.base.b, androidx.fragment.app.I, androidx.activity.s, androidx.core.app.AbstractActivityC1021h, android.app.Activity
    public final void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        v.b(this, null, 3);
        FragmentContainerView fragmentContainer = ((com.quizlet.explanations.databinding.a) K()).b;
        Intrinsics.checkNotNullExpressionValue(fragmentContainer, "fragmentContainer");
        AbstractC3188k6.a(fragmentContainer);
        if (this.q == null) {
            Intrinsics.m("navigator");
            throw null;
        }
        AbstractC1136h0 fragmentManager = getSupportFragmentManager();
        Intrinsics.checkNotNullExpressionValue(fragmentManager, "getSupportFragmentManager(...)");
        int id = ((FragmentContainerView) this.r.getValue()).getId();
        QuestionDetailSetUpState setUpState = (QuestionDetailSetUpState) this.s.getValue();
        Intrinsics.checkNotNullParameter(fragmentManager, "fragmentManager");
        Intrinsics.checkNotNullParameter(setUpState, "setUpState");
        String str = QuestionDetailFragment.v;
        Intrinsics.checkNotNullParameter(setUpState, "setUpState");
        QuestionDetailFragment questionDetailFragment = new QuestionDetailFragment();
        Bundle bundle2 = new Bundle();
        bundle2.putParcelable("question_detail_set_up_state", setUpState);
        String str2 = QuestionDetailFragment.v;
        bundle2.putString("question_detail_screen_name", str2);
        questionDetailFragment.setArguments(bundle2);
        fragmentManager.getClass();
        C1121a c1121a = new C1121a(fragmentManager);
        c1121a.l(id, questionDetailFragment, str2);
        c1121a.g();
    }
}

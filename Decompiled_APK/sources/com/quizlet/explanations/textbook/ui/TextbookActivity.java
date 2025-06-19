package com.quizlet.explanations.textbook.ui;

import android.content.Intent;
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
import com.onetrust.otpublishers.headless.Internal.Helper.h;
import com.quizlet.explanations.textbook.data.TextbookSetUpState;
import com.quizlet.quizletandroid.R;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes2.dex */
public final class TextbookActivity extends com.quizlet.ads.ui.activity.d {
    public static final String r;
    public h q;

    static {
        Intrinsics.checkNotNullExpressionValue("TextbookActivity", "getSimpleName(...)");
        r = "TextbookActivity";
    }

    public TextbookActivity() {
        super(2);
    }

    @Override // com.quizlet.baseui.base.b
    public final String D() {
        return r;
    }

    @Override // com.quizlet.baseui.base.f
    public final androidx.viewbinding.a N() {
        View viewInflate = getLayoutInflater().inflate(R.layout.activity_textbook, (ViewGroup) null, false);
        FragmentContainerView fragmentContainerView = (FragmentContainerView) AbstractC3375o2.c(R.id.fragmentContainer, viewInflate);
        if (fragmentContainerView == null) {
            throw new NullPointerException("Missing required view with ID: ".concat(viewInflate.getResources().getResourceName(R.id.fragmentContainer)));
        }
        com.quizlet.explanations.databinding.b bVar = new com.quizlet.explanations.databinding.b((ConstraintLayout) viewInflate, fragmentContainerView);
        Intrinsics.checkNotNullExpressionValue(bVar, "inflate(...)");
        return bVar;
    }

    public final void b0(Intent intent) {
        if (this.q == null) {
            Intrinsics.m("textbookActivityNavigator");
            throw null;
        }
        AbstractC1136h0 fragmentManager = getSupportFragmentManager();
        Intrinsics.checkNotNullExpressionValue(fragmentManager, "getSupportFragmentManager(...)");
        TextbookSetUpState state = (TextbookSetUpState) intent.getParcelableExtra("EXTRA_TEXTBOOK_STATE");
        if (state == null) {
            throw new IllegalStateException("Missing required extra (EXTRA_TEXTBOOK_STATE)");
        }
        Intrinsics.checkNotNullParameter(fragmentManager, "fragmentManager");
        Intrinsics.checkNotNullParameter(state, "state");
        fragmentManager.getClass();
        C1121a c1121a = new C1121a(fragmentManager);
        String str = TextbookFragment.l;
        Intrinsics.checkNotNullParameter(state, "state");
        TextbookFragment textbookFragment = new TextbookFragment();
        Bundle bundle = new Bundle();
        bundle.putParcelable("ARG_TEXTBOOK_SET_UP_STATE", state);
        textbookFragment.setArguments(bundle);
        c1121a.l(R.id.fragmentContainer, textbookFragment, TextbookFragment.l);
        c1121a.g();
    }

    @Override // com.quizlet.ads.ui.activity.d, com.quizlet.baseui.base.f, com.quizlet.baseui.base.b, androidx.fragment.app.I, androidx.activity.s, androidx.core.app.AbstractActivityC1021h, android.app.Activity
    public final void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        v.b(this, null, 3);
        FragmentContainerView fragmentContainer = ((com.quizlet.explanations.databinding.b) K()).b;
        Intrinsics.checkNotNullExpressionValue(fragmentContainer, "fragmentContainer");
        AbstractC3188k6.a(fragmentContainer);
        b0(getIntent());
    }

    @Override // androidx.activity.s, android.app.Activity
    public final void onNewIntent(Intent intent) {
        Intrinsics.checkNotNullParameter(intent, "intent");
        super.onNewIntent(intent);
        b0(intent);
    }
}

package com.quizlet.explanations.textbook.ui;

import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.node.B;
import androidx.fragment.app.AbstractC1136h0;
import androidx.fragment.app.C1121a;
import androidx.navigation.compose.C1278k;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3178j5;
import com.onetrust.otpublishers.headless.UI.fragment.C4062f;
import com.quizlet.baseui.base.BaseFragment;
import com.quizlet.explanations.textbook.data.TextbookSetUpState;
import com.quizlet.quizletandroid.R;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;
import kotlin.k;
import kotlin.l;
import kotlin.m;

@Metadata
/* loaded from: classes2.dex */
public final class TextbookFragment extends Hilt_TextbookFragment<androidx.viewbinding.a> {
    public static final String l;
    public final com.quizlet.data.repository.folderwithcreatorinclass.e j;
    public final InterfaceC0773a0 k;

    static {
        Intrinsics.checkNotNullExpressionValue("TextbookFragment", "getSimpleName(...)");
        l = "TextbookFragment";
    }

    public TextbookFragment() {
        k kVarA = l.a(m.c, new assistantMode.experiments.a(new assistantMode.experiments.a(this, 21), 22));
        this.j = new com.quizlet.data.repository.folderwithcreatorinclass.e(K.a(com.quizlet.explanations.textbook.viewmodel.c.class), new C4062f(kVarA, 24), new androidx.credentials.playservices.controllers.BeginSignIn.d(22, this, kVarA), new C4062f(kVarA, 25));
        this.k = C0776c.z(Boolean.FALSE);
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final String N() {
        return l;
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final androidx.viewbinding.a O(LayoutInflater inflater, ViewGroup viewGroup) {
        Intrinsics.checkNotNullParameter(inflater, "inflater");
        return new com.quizlet.explanations.myexplanations.ui.recyclerview.c(this, 9);
    }

    public final void T(InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-160858627);
        if ((((c0814p.h(this) ? 4 : 2) | i) & 3) == 2 && c0814p.x()) {
            c0814p.Q();
        } else {
            AbstractC3178j5.b(null, false, null, androidx.compose.runtime.internal.e.e(-528410467, new e(this, 0), c0814p), c0814p, 3072, 7);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C1278k(this, i, 4);
        }
    }

    public final void U(int i, BaseFragment baseFragment, String str, boolean z) {
        AbstractC1136h0 childFragmentManager = getChildFragmentManager();
        C1121a c1121aB = B.b(childFragmentManager, childFragmentManager);
        if (z) {
            c1121aB.d(str);
        }
        c1121aB.m(R.anim.slide_in_right, R.anim.slide_out_right);
        c1121aB.l(i, baseFragment, str);
        c1121aB.g();
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        com.quizlet.explanations.textbook.viewmodel.c cVar = (com.quizlet.explanations.textbook.viewmodel.c) this.j.getValue();
        TextbookSetUpState state = (TextbookSetUpState) requireArguments().getParcelable("ARG_TEXTBOOK_SET_UP_STATE");
        if (state == null) {
            throw new IllegalStateException("Missing required argument (ARG_TEXTBOOK_SET_UP_STATE)");
        }
        cVar.getClass();
        Intrinsics.checkNotNullParameter(state, "state");
        if (Intrinsics.b(cVar.l, state)) {
            return;
        }
        cVar.l = state;
        cVar.E(state);
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onViewCreated(View view, Bundle bundle) {
        Intrinsics.checkNotNullParameter(view, "view");
        super.onViewCreated(view, bundle);
        int i = 0;
        getChildFragmentManager().b(new b(this, i));
        AbstractC1136h0 childFragmentManager = getChildFragmentManager();
        childFragmentManager.o.add(new c(this, i));
        com.quizlet.data.repository.folderwithcreatorinclass.e eVar = this.j;
        ((com.quizlet.explanations.textbook.viewmodel.c) eVar.getValue()).j.f(getViewLifecycleOwner(), new com.quizlet.explanations.feedback.ui.fragments.c(5, new com.quizlet.explanations.solution.fragments.b(1, this, TextbookFragment.class, "showShareSheet", "showShareSheet(Lcom/quizlet/explanations/sharing/ExplanationsShareResData;)V", 0, 29)));
        ((com.quizlet.explanations.textbook.viewmodel.c) eVar.getValue()).k.f(getViewLifecycleOwner(), new com.quizlet.explanations.feedback.ui.fragments.c(5, new f(1, this, TextbookFragment.class, "showErrorState", "showErrorState(Lcom/quizlet/uicommon/ui/states/GeneralErrorDialogState;)V", 0, 0)));
    }
}

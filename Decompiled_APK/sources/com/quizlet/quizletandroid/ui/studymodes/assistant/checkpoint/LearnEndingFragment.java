package com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint;

import android.content.Context;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.lifecycle.C;
import androidx.lifecycle.J;
import androidx.lifecycle.X;
import androidx.lifecycle.p0;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3178j5;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3205m5;
import com.quizlet.eventlogger.model.LearnPostCompletionEventLog;
import com.quizlet.learn.data.AbstractC4543h;
import com.quizlet.learn.data.C4541f;
import com.quizlet.learn.data.C4542g;
import com.quizlet.learn.data.C4544i;
import com.quizlet.learn.viewmodel.C4556c;
import com.quizlet.learn.viewmodel.G;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;
import kotlinx.coroutines.E;
import kotlinx.coroutines.flow.Z;

@Metadata
/* loaded from: classes3.dex */
public final class LearnEndingFragment extends Hilt_LearnEndingFragment<androidx.viewbinding.a> {
    public static final String m;
    public com.quizlet.features.infra.ui.feedback.sound.soundeffect.e j;
    public final com.quizlet.data.repository.folderwithcreatorinclass.e k;
    public final com.quizlet.data.repository.folderwithcreatorinclass.e l;

    static {
        Intrinsics.checkNotNullExpressionValue("LearnEndingFragment", "getSimpleName(...)");
        m = "LearnEndingFragment";
    }

    public LearnEndingFragment() {
        kotlin.k kVarA = kotlin.l.a(kotlin.m.c, new com.quizlet.login.recovery.forgotpassword.ui.e(new n(this, 3), 24));
        this.k = new com.quizlet.data.repository.folderwithcreatorinclass.e(K.a(C4556c.class), new i(kVarA, 2), new com.quizlet.quizletandroid.ui.activitycenter.fragments.h(this, kVarA, 15), new i(kVarA, 3));
        this.l = new com.quizlet.data.repository.folderwithcreatorinclass.e(K.a(G.class), new n(this, 0), new n(this, 2), new n(this, 1));
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final String N() {
        return m;
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final androidx.viewbinding.a O(LayoutInflater inflater, ViewGroup viewGroup) {
        Intrinsics.checkNotNullParameter(inflater, "inflater");
        return new com.quizlet.explanations.myexplanations.ui.recyclerview.c(this, 26);
    }

    public final void T(InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1320695239);
        if ((((c0814p.h(this) ? 4 : 2) | i) & 3) == 2 && c0814p.x()) {
            c0814p.Q();
        } else {
            Context contextRequireContext = requireContext();
            Intrinsics.checkNotNullExpressionValue(contextRequireContext, "requireContext(...)");
            AbstractC3178j5.b(null, false, null, androidx.compose.runtime.internal.e.e(1759828889, new com.quizlet.quizletandroid.ui.startpage.nav2.viewholder.x(AbstractC3205m5.e(contextRequireContext), this, C0776c.m(new Z(((C4556c) this.k.getValue()).h), c0814p), 1), c0814p), c0814p, 3072, 7);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.settings.composables.dialogs.a(this, i, 12);
        }
    }

    public final G U() {
        return (G) this.l.getValue();
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        C lifecycle = getLifecycle();
        com.quizlet.features.infra.ui.feedback.sound.soundeffect.e eVar = this.j;
        if (eVar != null) {
            lifecycle.a(eVar);
        } else {
            Intrinsics.m("soundEffectPlayer");
            throw null;
        }
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onViewCreated(View view, Bundle bundle) {
        Intrinsics.checkNotNullParameter(view, "view");
        super.onViewCreated(view, bundle);
        final int i = 0;
        U().L.f(getViewLifecycleOwner(), new com.quizlet.explanations.feedback.ui.fragments.c(21, new Function1(this) { // from class: com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.k
            public final /* synthetic */ LearnEndingFragment b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object obj) {
                LearnEndingFragment learnEndingFragment = this.b;
                switch (i) {
                    case 0:
                        String str = LearnEndingFragment.m;
                        if (Intrinsics.b((com.quizlet.learn.data.t) obj, C4544i.a)) {
                            C4556c c4556c = (C4556c) learnEndingFragment.k.getValue();
                            String progressState = c4556c.g.a;
                            com.quizlet.learn.logging.d dVar = c4556c.d;
                            dVar.getClass();
                            Intrinsics.checkNotNullParameter("close", "buttonName");
                            Intrinsics.checkNotNullParameter(progressState, "progressState");
                            LearnPostCompletionEventLog.Companion companion = LearnPostCompletionEventLog.b;
                            com.braze.ui.e eVar = new com.braze.ui.e(8, "close", progressState);
                            companion.getClass();
                            dVar.a.l(LearnPostCompletionEventLog.Companion.a("learn_ending_button_clicked", eVar));
                        }
                        return Unit.a;
                    default:
                        AbstractC4543h it2 = (AbstractC4543h) obj;
                        String str2 = LearnEndingFragment.m;
                        Intrinsics.checkNotNullParameter(it2, "it");
                        if (it2 instanceof C4541f) {
                            learnEndingFragment.U().D();
                        } else {
                            if (!(it2 instanceof C4542g)) {
                                throw new NoWhenBranchMatchedException();
                            }
                            G gU = learnEndingFragment.U();
                            gU.getClass();
                            G.G(gU, false, 7);
                        }
                        return Unit.a;
                }
            }
        }));
        X x = ((C4556c) this.k.getValue()).i;
        J viewLifecycleOwner = getViewLifecycleOwner();
        Intrinsics.checkNotNullExpressionValue(viewLifecycleOwner, "getViewLifecycleOwner(...)");
        final int i2 = 1;
        x.f(viewLifecycleOwner, new com.quizlet.explanations.feedback.ui.fragments.c(21, new Function1(this) { // from class: com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.k
            public final /* synthetic */ LearnEndingFragment b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object obj) {
                LearnEndingFragment learnEndingFragment = this.b;
                switch (i2) {
                    case 0:
                        String str = LearnEndingFragment.m;
                        if (Intrinsics.b((com.quizlet.learn.data.t) obj, C4544i.a)) {
                            C4556c c4556c = (C4556c) learnEndingFragment.k.getValue();
                            String progressState = c4556c.g.a;
                            com.quizlet.learn.logging.d dVar = c4556c.d;
                            dVar.getClass();
                            Intrinsics.checkNotNullParameter("close", "buttonName");
                            Intrinsics.checkNotNullParameter(progressState, "progressState");
                            LearnPostCompletionEventLog.Companion companion = LearnPostCompletionEventLog.b;
                            com.braze.ui.e eVar = new com.braze.ui.e(8, "close", progressState);
                            companion.getClass();
                            dVar.a.l(LearnPostCompletionEventLog.Companion.a("learn_ending_button_clicked", eVar));
                        }
                        return Unit.a;
                    default:
                        AbstractC4543h it2 = (AbstractC4543h) obj;
                        String str2 = LearnEndingFragment.m;
                        Intrinsics.checkNotNullParameter(it2, "it");
                        if (it2 instanceof C4541f) {
                            learnEndingFragment.U().D();
                        } else {
                            if (!(it2 instanceof C4542g)) {
                                throw new NoWhenBranchMatchedException();
                            }
                            G gU = learnEndingFragment.U();
                            gU.getClass();
                            G.G(gU, false, 7);
                        }
                        return Unit.a;
                }
            }
        }));
        J viewLifecycleOwner2 = getViewLifecycleOwner();
        Intrinsics.checkNotNullExpressionValue(viewLifecycleOwner2, "getViewLifecycleOwner(...)");
        E.A(p0.h(viewLifecycleOwner2), null, null, new m(this, null), 3);
    }
}

package com.quizlet.quizletandroid.ui.studymodes.match.fragment;

import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.quizlet.features.match.data.AbstractC4352h;
import com.quizlet.features.match.data.C;
import com.quizlet.features.match.data.C4345a;
import com.quizlet.features.match.data.C4350f;
import com.quizlet.features.match.data.C4351g;
import com.quizlet.features.match.data.C4360p;
import com.quizlet.features.match.data.C4364u;
import com.quizlet.features.match.data.b0;
import com.quizlet.features.match.data.c0;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.databinding.A;
import com.quizlet.quizletandroid.ui.studymodes.match.view.MatchCardView;
import java.util.List;
import java.util.Objects;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.collections.B;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;

@Metadata
/* loaded from: classes3.dex */
public final class StandardMatchGameFragment extends Hilt_StandardMatchGameFragment<A> {
    public static final String r;
    public com.quizlet.qutils.image.loading.a j;
    public com.quizlet.quizletandroid.managers.audio.h k;
    public io.ktor.client.plugins.api.d l;
    public com.quizlet.richtext.rendering.c m;
    public com.quizlet.quizletandroid.util.f n;
    public final com.quizlet.data.repository.folderwithcreatorinclass.e o = new com.quizlet.data.repository.folderwithcreatorinclass.e(K.a(com.quizlet.features.match.viewmodel.f.class), new s(this, 0), new s(this, 2), new s(this, 1));
    public final com.quizlet.data.repository.folderwithcreatorinclass.e p;
    public List q;

    static {
        Intrinsics.checkNotNullExpressionValue("StandardMatchGameFragment", "getSimpleName(...)");
        r = "StandardMatchGameFragment";
    }

    public StandardMatchGameFragment() {
        com.quizlet.quizletandroid.ui.studymodes.assistant.settings.grading.a aVar = new com.quizlet.quizletandroid.ui.studymodes.assistant.settings.grading.a(this, 4);
        kotlin.k kVarA = kotlin.l.a(kotlin.m.c, new t(new t(this, 0), 1));
        this.p = new com.quizlet.data.repository.folderwithcreatorinclass.e(K.a(com.quizlet.features.match.viewmodel.i.class), new com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.i(kVarA, 8), new com.quizlet.quizletandroid.ui.activitycenter.fragments.h(this, kVarA, 25), new com.quizlet.quizletandroid.ui.activitycenter.fragments.h(aVar, kVarA, 24));
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final String N() {
        return r;
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final androidx.viewbinding.a O(LayoutInflater inflater, ViewGroup viewGroup) {
        Intrinsics.checkNotNullParameter(inflater, "inflater");
        View viewInflate = inflater.inflate(R.layout.fragment_match_game_standard, viewGroup, false);
        int i = R.id.matchSquare1;
        MatchCardView matchCardView = (MatchCardView) AbstractC3375o2.c(R.id.matchSquare1, viewInflate);
        if (matchCardView != null) {
            i = R.id.matchSquare10;
            MatchCardView matchCardView2 = (MatchCardView) AbstractC3375o2.c(R.id.matchSquare10, viewInflate);
            if (matchCardView2 != null) {
                i = R.id.matchSquare11;
                MatchCardView matchCardView3 = (MatchCardView) AbstractC3375o2.c(R.id.matchSquare11, viewInflate);
                if (matchCardView3 != null) {
                    i = R.id.matchSquare12;
                    MatchCardView matchCardView4 = (MatchCardView) AbstractC3375o2.c(R.id.matchSquare12, viewInflate);
                    if (matchCardView4 != null) {
                        i = R.id.matchSquare2;
                        MatchCardView matchCardView5 = (MatchCardView) AbstractC3375o2.c(R.id.matchSquare2, viewInflate);
                        if (matchCardView5 != null) {
                            i = R.id.matchSquare3;
                            MatchCardView matchCardView6 = (MatchCardView) AbstractC3375o2.c(R.id.matchSquare3, viewInflate);
                            if (matchCardView6 != null) {
                                i = R.id.matchSquare4;
                                MatchCardView matchCardView7 = (MatchCardView) AbstractC3375o2.c(R.id.matchSquare4, viewInflate);
                                if (matchCardView7 != null) {
                                    i = R.id.matchSquare5;
                                    MatchCardView matchCardView8 = (MatchCardView) AbstractC3375o2.c(R.id.matchSquare5, viewInflate);
                                    if (matchCardView8 != null) {
                                        i = R.id.matchSquare6;
                                        MatchCardView matchCardView9 = (MatchCardView) AbstractC3375o2.c(R.id.matchSquare6, viewInflate);
                                        if (matchCardView9 != null) {
                                            i = R.id.matchSquare7;
                                            MatchCardView matchCardView10 = (MatchCardView) AbstractC3375o2.c(R.id.matchSquare7, viewInflate);
                                            if (matchCardView10 != null) {
                                                i = R.id.matchSquare8;
                                                MatchCardView matchCardView11 = (MatchCardView) AbstractC3375o2.c(R.id.matchSquare8, viewInflate);
                                                if (matchCardView11 != null) {
                                                    i = R.id.matchSquare9;
                                                    MatchCardView matchCardView12 = (MatchCardView) AbstractC3375o2.c(R.id.matchSquare9, viewInflate);
                                                    if (matchCardView12 != null) {
                                                        A a = new A((LinearLayout) viewInflate, matchCardView, matchCardView2, matchCardView3, matchCardView4, matchCardView5, matchCardView6, matchCardView7, matchCardView8, matchCardView9, matchCardView10, matchCardView11, matchCardView12);
                                                        Intrinsics.checkNotNullExpressionValue(a, "inflate(...)");
                                                        return a;
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

    public final void T(List list) {
        List list2 = this.q;
        if (list2 == null) {
            Intrinsics.m("cards");
            throw null;
        }
        int i = 0;
        for (Object obj : list2) {
            int i2 = i + 1;
            if (i < 0) {
                B.p();
                throw null;
            }
            MatchCardView matchCardView = (MatchCardView) obj;
            if (B.i(list) < i) {
                matchCardView.f();
                matchCardView.setVisibility(4);
            } else {
                matchCardView.setVisibility(0);
                matchCardView.c((C4345a) list.get(i));
            }
            i = i2;
        }
    }

    public final com.quizlet.features.match.viewmodel.i U() {
        return (com.quizlet.features.match.viewmodel.i) this.p.getValue();
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        final int i = 0;
        U().e.f(this, new com.quizlet.explanations.feedback.ui.fragments.c(24, new Function1(this) { // from class: com.quizlet.quizletandroid.ui.studymodes.match.fragment.q
            public final /* synthetic */ StandardMatchGameFragment b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object obj) {
                final int i2 = 1;
                final int i3 = 2;
                final StandardMatchGameFragment standardMatchGameFragment = this.b;
                final int i4 = 0;
                switch (i) {
                    case 0:
                        String str = StandardMatchGameFragment.r;
                        ((com.quizlet.features.match.viewmodel.f) standardMatchGameFragment.o.getValue()).B();
                        return Unit.a;
                    case 1:
                        String str2 = StandardMatchGameFragment.r;
                        com.quizlet.features.match.viewmodel.f fVar = (com.quizlet.features.match.viewmodel.f) standardMatchGameFragment.o.getValue();
                        com.quizlet.features.match.studyengine.e eVar = (com.quizlet.features.match.studyengine.e) fVar.c;
                        eVar.b();
                        eVar.g = System.currentTimeMillis();
                        fVar.e.l(C4360p.a);
                        return Unit.a;
                    case 2:
                        C c = (C) obj;
                        String str3 = StandardMatchGameFragment.r;
                        if (c instanceof com.quizlet.features.match.data.A) {
                            standardMatchGameFragment.T(((b0) ((com.quizlet.features.match.data.A) c).a).a);
                        } else {
                            if (!Intrinsics.b(c, com.quizlet.features.match.data.B.a)) {
                                throw new NoWhenBranchMatchedException();
                            }
                            standardMatchGameFragment.T(kotlin.collections.K.a);
                            com.quizlet.features.match.viewmodel.f fVar2 = (com.quizlet.features.match.viewmodel.f) standardMatchGameFragment.o.getValue();
                            com.quizlet.features.match.studyengine.e eVar2 = (com.quizlet.features.match.studyengine.e) fVar2.c;
                            fVar2.d.o(new C4364u(eVar2.g, eVar2.h));
                        }
                        return Unit.a;
                    default:
                        AbstractC4352h abstractC4352h = (AbstractC4352h) obj;
                        String str4 = StandardMatchGameFragment.r;
                        boolean z = abstractC4352h instanceof C4350f;
                        com.quizlet.infra.legacysyncengine.net.request.g gVar = io.reactivex.rxjava3.internal.functions.d.e;
                        io.reactivex.rxjava3.internal.functions.b bVar = io.reactivex.rxjava3.internal.functions.d.c;
                        com.quizlet.infra.legacysyncengine.net.request.g gVar2 = io.reactivex.rxjava3.internal.functions.d.d;
                        if (z) {
                            final c0 c0Var = (c0) ((C4350f) abstractC4352h).a;
                            List list = standardMatchGameFragment.q;
                            if (list == null) {
                                Intrinsics.m("cards");
                                throw null;
                            }
                            io.reactivex.rxjava3.subjects.f fVarD = ((MatchCardView) list.get(c0Var.b)).d();
                            List list2 = standardMatchGameFragment.q;
                            if (list2 == null) {
                                Intrinsics.m("cards");
                                throw null;
                            }
                            List listJ = B.j(fVarD, ((MatchCardView) list2.get(c0Var.c)).d());
                            Objects.requireNonNull(listJ, "sources is null");
                            io.reactivex.rxjava3.internal.operators.completable.i iVar = new io.reactivex.rxjava3.internal.operators.completable.i(new io.reactivex.rxjava3.internal.operators.completable.c(listJ, 0), gVar2, gVar2, bVar, new io.reactivex.rxjava3.functions.a() { // from class: com.quizlet.quizletandroid.ui.studymodes.match.fragment.r
                                @Override // io.reactivex.rxjava3.functions.a
                                public final void run() {
                                    c0 c0Var2 = c0Var;
                                    StandardMatchGameFragment standardMatchGameFragment2 = standardMatchGameFragment;
                                    switch (i3) {
                                        case 0:
                                            String str5 = StandardMatchGameFragment.r;
                                            standardMatchGameFragment2.U().H(c0Var2);
                                            break;
                                        case 1:
                                            String str6 = StandardMatchGameFragment.r;
                                            standardMatchGameFragment2.U().H(c0Var2);
                                            break;
                                        case 2:
                                            String str7 = StandardMatchGameFragment.r;
                                            standardMatchGameFragment2.U().G(c0Var2);
                                            break;
                                        default:
                                            String str8 = StandardMatchGameFragment.r;
                                            standardMatchGameFragment2.U().G(c0Var2);
                                            break;
                                    }
                                }
                            });
                            final int i5 = 3;
                            io.reactivex.rxjava3.internal.observers.e eVarF = iVar.f(new io.reactivex.rxjava3.functions.a() { // from class: com.quizlet.quizletandroid.ui.studymodes.match.fragment.r
                                @Override // io.reactivex.rxjava3.functions.a
                                public final void run() {
                                    c0 c0Var2 = c0Var;
                                    StandardMatchGameFragment standardMatchGameFragment2 = standardMatchGameFragment;
                                    switch (i5) {
                                        case 0:
                                            String str5 = StandardMatchGameFragment.r;
                                            standardMatchGameFragment2.U().H(c0Var2);
                                            break;
                                        case 1:
                                            String str6 = StandardMatchGameFragment.r;
                                            standardMatchGameFragment2.U().H(c0Var2);
                                            break;
                                        case 2:
                                            String str7 = StandardMatchGameFragment.r;
                                            standardMatchGameFragment2.U().G(c0Var2);
                                            break;
                                        default:
                                            String str8 = StandardMatchGameFragment.r;
                                            standardMatchGameFragment2.U().G(c0Var2);
                                            break;
                                    }
                                }
                            }, gVar);
                            Intrinsics.checkNotNullExpressionValue(eVarF, "subscribe(...)");
                            standardMatchGameFragment.I(eVarF);
                        } else {
                            if (!(abstractC4352h instanceof C4351g)) {
                                throw new NoWhenBranchMatchedException();
                            }
                            final c0 c0Var2 = (c0) ((C4351g) abstractC4352h).a;
                            ((com.quizlet.features.match.viewmodel.f) standardMatchGameFragment.o.getValue()).C();
                            List list3 = standardMatchGameFragment.q;
                            if (list3 == null) {
                                Intrinsics.m("cards");
                                throw null;
                            }
                            io.reactivex.rxjava3.subjects.f fVarE = ((MatchCardView) list3.get(c0Var2.b)).e();
                            List list4 = standardMatchGameFragment.q;
                            if (list4 == null) {
                                Intrinsics.m("cards");
                                throw null;
                            }
                            List listJ2 = B.j(fVarE, ((MatchCardView) list4.get(c0Var2.c)).e());
                            Objects.requireNonNull(listJ2, "sources is null");
                            io.reactivex.rxjava3.internal.observers.e eVarF2 = new io.reactivex.rxjava3.internal.operators.completable.i(new io.reactivex.rxjava3.internal.operators.completable.c(listJ2, 0), gVar2, gVar2, bVar, new io.reactivex.rxjava3.functions.a() { // from class: com.quizlet.quizletandroid.ui.studymodes.match.fragment.r
                                @Override // io.reactivex.rxjava3.functions.a
                                public final void run() {
                                    c0 c0Var22 = c0Var2;
                                    StandardMatchGameFragment standardMatchGameFragment2 = standardMatchGameFragment;
                                    switch (i4) {
                                        case 0:
                                            String str5 = StandardMatchGameFragment.r;
                                            standardMatchGameFragment2.U().H(c0Var22);
                                            break;
                                        case 1:
                                            String str6 = StandardMatchGameFragment.r;
                                            standardMatchGameFragment2.U().H(c0Var22);
                                            break;
                                        case 2:
                                            String str7 = StandardMatchGameFragment.r;
                                            standardMatchGameFragment2.U().G(c0Var22);
                                            break;
                                        default:
                                            String str8 = StandardMatchGameFragment.r;
                                            standardMatchGameFragment2.U().G(c0Var22);
                                            break;
                                    }
                                }
                            }).f(new io.reactivex.rxjava3.functions.a() { // from class: com.quizlet.quizletandroid.ui.studymodes.match.fragment.r
                                @Override // io.reactivex.rxjava3.functions.a
                                public final void run() {
                                    c0 c0Var22 = c0Var2;
                                    StandardMatchGameFragment standardMatchGameFragment2 = standardMatchGameFragment;
                                    switch (i2) {
                                        case 0:
                                            String str5 = StandardMatchGameFragment.r;
                                            standardMatchGameFragment2.U().H(c0Var22);
                                            break;
                                        case 1:
                                            String str6 = StandardMatchGameFragment.r;
                                            standardMatchGameFragment2.U().H(c0Var22);
                                            break;
                                        case 2:
                                            String str7 = StandardMatchGameFragment.r;
                                            standardMatchGameFragment2.U().G(c0Var22);
                                            break;
                                        default:
                                            String str8 = StandardMatchGameFragment.r;
                                            standardMatchGameFragment2.U().G(c0Var22);
                                            break;
                                    }
                                }
                            }, gVar);
                            Intrinsics.checkNotNullExpressionValue(eVarF2, "subscribe(...)");
                            standardMatchGameFragment.I(eVarF2);
                        }
                        return Unit.a;
                }
            }
        }));
        final int i2 = 1;
        U().f.f(this, new com.quizlet.explanations.feedback.ui.fragments.c(24, new Function1(this) { // from class: com.quizlet.quizletandroid.ui.studymodes.match.fragment.q
            public final /* synthetic */ StandardMatchGameFragment b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object obj) {
                final int i22 = 1;
                final int i3 = 2;
                final StandardMatchGameFragment standardMatchGameFragment = this.b;
                final int i4 = 0;
                switch (i2) {
                    case 0:
                        String str = StandardMatchGameFragment.r;
                        ((com.quizlet.features.match.viewmodel.f) standardMatchGameFragment.o.getValue()).B();
                        return Unit.a;
                    case 1:
                        String str2 = StandardMatchGameFragment.r;
                        com.quizlet.features.match.viewmodel.f fVar = (com.quizlet.features.match.viewmodel.f) standardMatchGameFragment.o.getValue();
                        com.quizlet.features.match.studyengine.e eVar = (com.quizlet.features.match.studyengine.e) fVar.c;
                        eVar.b();
                        eVar.g = System.currentTimeMillis();
                        fVar.e.l(C4360p.a);
                        return Unit.a;
                    case 2:
                        C c = (C) obj;
                        String str3 = StandardMatchGameFragment.r;
                        if (c instanceof com.quizlet.features.match.data.A) {
                            standardMatchGameFragment.T(((b0) ((com.quizlet.features.match.data.A) c).a).a);
                        } else {
                            if (!Intrinsics.b(c, com.quizlet.features.match.data.B.a)) {
                                throw new NoWhenBranchMatchedException();
                            }
                            standardMatchGameFragment.T(kotlin.collections.K.a);
                            com.quizlet.features.match.viewmodel.f fVar2 = (com.quizlet.features.match.viewmodel.f) standardMatchGameFragment.o.getValue();
                            com.quizlet.features.match.studyengine.e eVar2 = (com.quizlet.features.match.studyengine.e) fVar2.c;
                            fVar2.d.o(new C4364u(eVar2.g, eVar2.h));
                        }
                        return Unit.a;
                    default:
                        AbstractC4352h abstractC4352h = (AbstractC4352h) obj;
                        String str4 = StandardMatchGameFragment.r;
                        boolean z = abstractC4352h instanceof C4350f;
                        com.quizlet.infra.legacysyncengine.net.request.g gVar = io.reactivex.rxjava3.internal.functions.d.e;
                        io.reactivex.rxjava3.internal.functions.b bVar = io.reactivex.rxjava3.internal.functions.d.c;
                        com.quizlet.infra.legacysyncengine.net.request.g gVar2 = io.reactivex.rxjava3.internal.functions.d.d;
                        if (z) {
                            final c0 c0Var = (c0) ((C4350f) abstractC4352h).a;
                            List list = standardMatchGameFragment.q;
                            if (list == null) {
                                Intrinsics.m("cards");
                                throw null;
                            }
                            io.reactivex.rxjava3.subjects.f fVarD = ((MatchCardView) list.get(c0Var.b)).d();
                            List list2 = standardMatchGameFragment.q;
                            if (list2 == null) {
                                Intrinsics.m("cards");
                                throw null;
                            }
                            List listJ = B.j(fVarD, ((MatchCardView) list2.get(c0Var.c)).d());
                            Objects.requireNonNull(listJ, "sources is null");
                            io.reactivex.rxjava3.internal.operators.completable.i iVar = new io.reactivex.rxjava3.internal.operators.completable.i(new io.reactivex.rxjava3.internal.operators.completable.c(listJ, 0), gVar2, gVar2, bVar, new io.reactivex.rxjava3.functions.a() { // from class: com.quizlet.quizletandroid.ui.studymodes.match.fragment.r
                                @Override // io.reactivex.rxjava3.functions.a
                                public final void run() {
                                    c0 c0Var22 = c0Var;
                                    StandardMatchGameFragment standardMatchGameFragment2 = standardMatchGameFragment;
                                    switch (i3) {
                                        case 0:
                                            String str5 = StandardMatchGameFragment.r;
                                            standardMatchGameFragment2.U().H(c0Var22);
                                            break;
                                        case 1:
                                            String str6 = StandardMatchGameFragment.r;
                                            standardMatchGameFragment2.U().H(c0Var22);
                                            break;
                                        case 2:
                                            String str7 = StandardMatchGameFragment.r;
                                            standardMatchGameFragment2.U().G(c0Var22);
                                            break;
                                        default:
                                            String str8 = StandardMatchGameFragment.r;
                                            standardMatchGameFragment2.U().G(c0Var22);
                                            break;
                                    }
                                }
                            });
                            final int i5 = 3;
                            io.reactivex.rxjava3.internal.observers.e eVarF = iVar.f(new io.reactivex.rxjava3.functions.a() { // from class: com.quizlet.quizletandroid.ui.studymodes.match.fragment.r
                                @Override // io.reactivex.rxjava3.functions.a
                                public final void run() {
                                    c0 c0Var22 = c0Var;
                                    StandardMatchGameFragment standardMatchGameFragment2 = standardMatchGameFragment;
                                    switch (i5) {
                                        case 0:
                                            String str5 = StandardMatchGameFragment.r;
                                            standardMatchGameFragment2.U().H(c0Var22);
                                            break;
                                        case 1:
                                            String str6 = StandardMatchGameFragment.r;
                                            standardMatchGameFragment2.U().H(c0Var22);
                                            break;
                                        case 2:
                                            String str7 = StandardMatchGameFragment.r;
                                            standardMatchGameFragment2.U().G(c0Var22);
                                            break;
                                        default:
                                            String str8 = StandardMatchGameFragment.r;
                                            standardMatchGameFragment2.U().G(c0Var22);
                                            break;
                                    }
                                }
                            }, gVar);
                            Intrinsics.checkNotNullExpressionValue(eVarF, "subscribe(...)");
                            standardMatchGameFragment.I(eVarF);
                        } else {
                            if (!(abstractC4352h instanceof C4351g)) {
                                throw new NoWhenBranchMatchedException();
                            }
                            final c0 c0Var2 = (c0) ((C4351g) abstractC4352h).a;
                            ((com.quizlet.features.match.viewmodel.f) standardMatchGameFragment.o.getValue()).C();
                            List list3 = standardMatchGameFragment.q;
                            if (list3 == null) {
                                Intrinsics.m("cards");
                                throw null;
                            }
                            io.reactivex.rxjava3.subjects.f fVarE = ((MatchCardView) list3.get(c0Var2.b)).e();
                            List list4 = standardMatchGameFragment.q;
                            if (list4 == null) {
                                Intrinsics.m("cards");
                                throw null;
                            }
                            List listJ2 = B.j(fVarE, ((MatchCardView) list4.get(c0Var2.c)).e());
                            Objects.requireNonNull(listJ2, "sources is null");
                            io.reactivex.rxjava3.internal.observers.e eVarF2 = new io.reactivex.rxjava3.internal.operators.completable.i(new io.reactivex.rxjava3.internal.operators.completable.c(listJ2, 0), gVar2, gVar2, bVar, new io.reactivex.rxjava3.functions.a() { // from class: com.quizlet.quizletandroid.ui.studymodes.match.fragment.r
                                @Override // io.reactivex.rxjava3.functions.a
                                public final void run() {
                                    c0 c0Var22 = c0Var2;
                                    StandardMatchGameFragment standardMatchGameFragment2 = standardMatchGameFragment;
                                    switch (i4) {
                                        case 0:
                                            String str5 = StandardMatchGameFragment.r;
                                            standardMatchGameFragment2.U().H(c0Var22);
                                            break;
                                        case 1:
                                            String str6 = StandardMatchGameFragment.r;
                                            standardMatchGameFragment2.U().H(c0Var22);
                                            break;
                                        case 2:
                                            String str7 = StandardMatchGameFragment.r;
                                            standardMatchGameFragment2.U().G(c0Var22);
                                            break;
                                        default:
                                            String str8 = StandardMatchGameFragment.r;
                                            standardMatchGameFragment2.U().G(c0Var22);
                                            break;
                                    }
                                }
                            }).f(new io.reactivex.rxjava3.functions.a() { // from class: com.quizlet.quizletandroid.ui.studymodes.match.fragment.r
                                @Override // io.reactivex.rxjava3.functions.a
                                public final void run() {
                                    c0 c0Var22 = c0Var2;
                                    StandardMatchGameFragment standardMatchGameFragment2 = standardMatchGameFragment;
                                    switch (i22) {
                                        case 0:
                                            String str5 = StandardMatchGameFragment.r;
                                            standardMatchGameFragment2.U().H(c0Var22);
                                            break;
                                        case 1:
                                            String str6 = StandardMatchGameFragment.r;
                                            standardMatchGameFragment2.U().H(c0Var22);
                                            break;
                                        case 2:
                                            String str7 = StandardMatchGameFragment.r;
                                            standardMatchGameFragment2.U().G(c0Var22);
                                            break;
                                        default:
                                            String str8 = StandardMatchGameFragment.r;
                                            standardMatchGameFragment2.U().G(c0Var22);
                                            break;
                                    }
                                }
                            }, gVar);
                            Intrinsics.checkNotNullExpressionValue(eVarF2, "subscribe(...)");
                            standardMatchGameFragment.I(eVarF2);
                        }
                        return Unit.a;
                }
            }
        }));
        final int i3 = 2;
        U().g.f(this, new com.quizlet.explanations.feedback.ui.fragments.c(24, new Function1(this) { // from class: com.quizlet.quizletandroid.ui.studymodes.match.fragment.q
            public final /* synthetic */ StandardMatchGameFragment b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object obj) {
                final int i22 = 1;
                final int i32 = 2;
                final StandardMatchGameFragment standardMatchGameFragment = this.b;
                final int i4 = 0;
                switch (i3) {
                    case 0:
                        String str = StandardMatchGameFragment.r;
                        ((com.quizlet.features.match.viewmodel.f) standardMatchGameFragment.o.getValue()).B();
                        return Unit.a;
                    case 1:
                        String str2 = StandardMatchGameFragment.r;
                        com.quizlet.features.match.viewmodel.f fVar = (com.quizlet.features.match.viewmodel.f) standardMatchGameFragment.o.getValue();
                        com.quizlet.features.match.studyengine.e eVar = (com.quizlet.features.match.studyengine.e) fVar.c;
                        eVar.b();
                        eVar.g = System.currentTimeMillis();
                        fVar.e.l(C4360p.a);
                        return Unit.a;
                    case 2:
                        C c = (C) obj;
                        String str3 = StandardMatchGameFragment.r;
                        if (c instanceof com.quizlet.features.match.data.A) {
                            standardMatchGameFragment.T(((b0) ((com.quizlet.features.match.data.A) c).a).a);
                        } else {
                            if (!Intrinsics.b(c, com.quizlet.features.match.data.B.a)) {
                                throw new NoWhenBranchMatchedException();
                            }
                            standardMatchGameFragment.T(kotlin.collections.K.a);
                            com.quizlet.features.match.viewmodel.f fVar2 = (com.quizlet.features.match.viewmodel.f) standardMatchGameFragment.o.getValue();
                            com.quizlet.features.match.studyengine.e eVar2 = (com.quizlet.features.match.studyengine.e) fVar2.c;
                            fVar2.d.o(new C4364u(eVar2.g, eVar2.h));
                        }
                        return Unit.a;
                    default:
                        AbstractC4352h abstractC4352h = (AbstractC4352h) obj;
                        String str4 = StandardMatchGameFragment.r;
                        boolean z = abstractC4352h instanceof C4350f;
                        com.quizlet.infra.legacysyncengine.net.request.g gVar = io.reactivex.rxjava3.internal.functions.d.e;
                        io.reactivex.rxjava3.internal.functions.b bVar = io.reactivex.rxjava3.internal.functions.d.c;
                        com.quizlet.infra.legacysyncengine.net.request.g gVar2 = io.reactivex.rxjava3.internal.functions.d.d;
                        if (z) {
                            final c0 c0Var = (c0) ((C4350f) abstractC4352h).a;
                            List list = standardMatchGameFragment.q;
                            if (list == null) {
                                Intrinsics.m("cards");
                                throw null;
                            }
                            io.reactivex.rxjava3.subjects.f fVarD = ((MatchCardView) list.get(c0Var.b)).d();
                            List list2 = standardMatchGameFragment.q;
                            if (list2 == null) {
                                Intrinsics.m("cards");
                                throw null;
                            }
                            List listJ = B.j(fVarD, ((MatchCardView) list2.get(c0Var.c)).d());
                            Objects.requireNonNull(listJ, "sources is null");
                            io.reactivex.rxjava3.internal.operators.completable.i iVar = new io.reactivex.rxjava3.internal.operators.completable.i(new io.reactivex.rxjava3.internal.operators.completable.c(listJ, 0), gVar2, gVar2, bVar, new io.reactivex.rxjava3.functions.a() { // from class: com.quizlet.quizletandroid.ui.studymodes.match.fragment.r
                                @Override // io.reactivex.rxjava3.functions.a
                                public final void run() {
                                    c0 c0Var22 = c0Var;
                                    StandardMatchGameFragment standardMatchGameFragment2 = standardMatchGameFragment;
                                    switch (i32) {
                                        case 0:
                                            String str5 = StandardMatchGameFragment.r;
                                            standardMatchGameFragment2.U().H(c0Var22);
                                            break;
                                        case 1:
                                            String str6 = StandardMatchGameFragment.r;
                                            standardMatchGameFragment2.U().H(c0Var22);
                                            break;
                                        case 2:
                                            String str7 = StandardMatchGameFragment.r;
                                            standardMatchGameFragment2.U().G(c0Var22);
                                            break;
                                        default:
                                            String str8 = StandardMatchGameFragment.r;
                                            standardMatchGameFragment2.U().G(c0Var22);
                                            break;
                                    }
                                }
                            });
                            final int i5 = 3;
                            io.reactivex.rxjava3.internal.observers.e eVarF = iVar.f(new io.reactivex.rxjava3.functions.a() { // from class: com.quizlet.quizletandroid.ui.studymodes.match.fragment.r
                                @Override // io.reactivex.rxjava3.functions.a
                                public final void run() {
                                    c0 c0Var22 = c0Var;
                                    StandardMatchGameFragment standardMatchGameFragment2 = standardMatchGameFragment;
                                    switch (i5) {
                                        case 0:
                                            String str5 = StandardMatchGameFragment.r;
                                            standardMatchGameFragment2.U().H(c0Var22);
                                            break;
                                        case 1:
                                            String str6 = StandardMatchGameFragment.r;
                                            standardMatchGameFragment2.U().H(c0Var22);
                                            break;
                                        case 2:
                                            String str7 = StandardMatchGameFragment.r;
                                            standardMatchGameFragment2.U().G(c0Var22);
                                            break;
                                        default:
                                            String str8 = StandardMatchGameFragment.r;
                                            standardMatchGameFragment2.U().G(c0Var22);
                                            break;
                                    }
                                }
                            }, gVar);
                            Intrinsics.checkNotNullExpressionValue(eVarF, "subscribe(...)");
                            standardMatchGameFragment.I(eVarF);
                        } else {
                            if (!(abstractC4352h instanceof C4351g)) {
                                throw new NoWhenBranchMatchedException();
                            }
                            final c0 c0Var2 = (c0) ((C4351g) abstractC4352h).a;
                            ((com.quizlet.features.match.viewmodel.f) standardMatchGameFragment.o.getValue()).C();
                            List list3 = standardMatchGameFragment.q;
                            if (list3 == null) {
                                Intrinsics.m("cards");
                                throw null;
                            }
                            io.reactivex.rxjava3.subjects.f fVarE = ((MatchCardView) list3.get(c0Var2.b)).e();
                            List list4 = standardMatchGameFragment.q;
                            if (list4 == null) {
                                Intrinsics.m("cards");
                                throw null;
                            }
                            List listJ2 = B.j(fVarE, ((MatchCardView) list4.get(c0Var2.c)).e());
                            Objects.requireNonNull(listJ2, "sources is null");
                            io.reactivex.rxjava3.internal.observers.e eVarF2 = new io.reactivex.rxjava3.internal.operators.completable.i(new io.reactivex.rxjava3.internal.operators.completable.c(listJ2, 0), gVar2, gVar2, bVar, new io.reactivex.rxjava3.functions.a() { // from class: com.quizlet.quizletandroid.ui.studymodes.match.fragment.r
                                @Override // io.reactivex.rxjava3.functions.a
                                public final void run() {
                                    c0 c0Var22 = c0Var2;
                                    StandardMatchGameFragment standardMatchGameFragment2 = standardMatchGameFragment;
                                    switch (i4) {
                                        case 0:
                                            String str5 = StandardMatchGameFragment.r;
                                            standardMatchGameFragment2.U().H(c0Var22);
                                            break;
                                        case 1:
                                            String str6 = StandardMatchGameFragment.r;
                                            standardMatchGameFragment2.U().H(c0Var22);
                                            break;
                                        case 2:
                                            String str7 = StandardMatchGameFragment.r;
                                            standardMatchGameFragment2.U().G(c0Var22);
                                            break;
                                        default:
                                            String str8 = StandardMatchGameFragment.r;
                                            standardMatchGameFragment2.U().G(c0Var22);
                                            break;
                                    }
                                }
                            }).f(new io.reactivex.rxjava3.functions.a() { // from class: com.quizlet.quizletandroid.ui.studymodes.match.fragment.r
                                @Override // io.reactivex.rxjava3.functions.a
                                public final void run() {
                                    c0 c0Var22 = c0Var2;
                                    StandardMatchGameFragment standardMatchGameFragment2 = standardMatchGameFragment;
                                    switch (i22) {
                                        case 0:
                                            String str5 = StandardMatchGameFragment.r;
                                            standardMatchGameFragment2.U().H(c0Var22);
                                            break;
                                        case 1:
                                            String str6 = StandardMatchGameFragment.r;
                                            standardMatchGameFragment2.U().H(c0Var22);
                                            break;
                                        case 2:
                                            String str7 = StandardMatchGameFragment.r;
                                            standardMatchGameFragment2.U().G(c0Var22);
                                            break;
                                        default:
                                            String str8 = StandardMatchGameFragment.r;
                                            standardMatchGameFragment2.U().G(c0Var22);
                                            break;
                                    }
                                }
                            }, gVar);
                            Intrinsics.checkNotNullExpressionValue(eVarF2, "subscribe(...)");
                            standardMatchGameFragment.I(eVarF2);
                        }
                        return Unit.a;
                }
            }
        }));
        final int i4 = 3;
        U().h.f(this, new com.quizlet.explanations.feedback.ui.fragments.c(24, new Function1(this) { // from class: com.quizlet.quizletandroid.ui.studymodes.match.fragment.q
            public final /* synthetic */ StandardMatchGameFragment b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object obj) {
                final int i22 = 1;
                final int i32 = 2;
                final StandardMatchGameFragment standardMatchGameFragment = this.b;
                final int i42 = 0;
                switch (i4) {
                    case 0:
                        String str = StandardMatchGameFragment.r;
                        ((com.quizlet.features.match.viewmodel.f) standardMatchGameFragment.o.getValue()).B();
                        return Unit.a;
                    case 1:
                        String str2 = StandardMatchGameFragment.r;
                        com.quizlet.features.match.viewmodel.f fVar = (com.quizlet.features.match.viewmodel.f) standardMatchGameFragment.o.getValue();
                        com.quizlet.features.match.studyengine.e eVar = (com.quizlet.features.match.studyengine.e) fVar.c;
                        eVar.b();
                        eVar.g = System.currentTimeMillis();
                        fVar.e.l(C4360p.a);
                        return Unit.a;
                    case 2:
                        C c = (C) obj;
                        String str3 = StandardMatchGameFragment.r;
                        if (c instanceof com.quizlet.features.match.data.A) {
                            standardMatchGameFragment.T(((b0) ((com.quizlet.features.match.data.A) c).a).a);
                        } else {
                            if (!Intrinsics.b(c, com.quizlet.features.match.data.B.a)) {
                                throw new NoWhenBranchMatchedException();
                            }
                            standardMatchGameFragment.T(kotlin.collections.K.a);
                            com.quizlet.features.match.viewmodel.f fVar2 = (com.quizlet.features.match.viewmodel.f) standardMatchGameFragment.o.getValue();
                            com.quizlet.features.match.studyengine.e eVar2 = (com.quizlet.features.match.studyengine.e) fVar2.c;
                            fVar2.d.o(new C4364u(eVar2.g, eVar2.h));
                        }
                        return Unit.a;
                    default:
                        AbstractC4352h abstractC4352h = (AbstractC4352h) obj;
                        String str4 = StandardMatchGameFragment.r;
                        boolean z = abstractC4352h instanceof C4350f;
                        com.quizlet.infra.legacysyncengine.net.request.g gVar = io.reactivex.rxjava3.internal.functions.d.e;
                        io.reactivex.rxjava3.internal.functions.b bVar = io.reactivex.rxjava3.internal.functions.d.c;
                        com.quizlet.infra.legacysyncengine.net.request.g gVar2 = io.reactivex.rxjava3.internal.functions.d.d;
                        if (z) {
                            final c0 c0Var = (c0) ((C4350f) abstractC4352h).a;
                            List list = standardMatchGameFragment.q;
                            if (list == null) {
                                Intrinsics.m("cards");
                                throw null;
                            }
                            io.reactivex.rxjava3.subjects.f fVarD = ((MatchCardView) list.get(c0Var.b)).d();
                            List list2 = standardMatchGameFragment.q;
                            if (list2 == null) {
                                Intrinsics.m("cards");
                                throw null;
                            }
                            List listJ = B.j(fVarD, ((MatchCardView) list2.get(c0Var.c)).d());
                            Objects.requireNonNull(listJ, "sources is null");
                            io.reactivex.rxjava3.internal.operators.completable.i iVar = new io.reactivex.rxjava3.internal.operators.completable.i(new io.reactivex.rxjava3.internal.operators.completable.c(listJ, 0), gVar2, gVar2, bVar, new io.reactivex.rxjava3.functions.a() { // from class: com.quizlet.quizletandroid.ui.studymodes.match.fragment.r
                                @Override // io.reactivex.rxjava3.functions.a
                                public final void run() {
                                    c0 c0Var22 = c0Var;
                                    StandardMatchGameFragment standardMatchGameFragment2 = standardMatchGameFragment;
                                    switch (i32) {
                                        case 0:
                                            String str5 = StandardMatchGameFragment.r;
                                            standardMatchGameFragment2.U().H(c0Var22);
                                            break;
                                        case 1:
                                            String str6 = StandardMatchGameFragment.r;
                                            standardMatchGameFragment2.U().H(c0Var22);
                                            break;
                                        case 2:
                                            String str7 = StandardMatchGameFragment.r;
                                            standardMatchGameFragment2.U().G(c0Var22);
                                            break;
                                        default:
                                            String str8 = StandardMatchGameFragment.r;
                                            standardMatchGameFragment2.U().G(c0Var22);
                                            break;
                                    }
                                }
                            });
                            final int i5 = 3;
                            io.reactivex.rxjava3.internal.observers.e eVarF = iVar.f(new io.reactivex.rxjava3.functions.a() { // from class: com.quizlet.quizletandroid.ui.studymodes.match.fragment.r
                                @Override // io.reactivex.rxjava3.functions.a
                                public final void run() {
                                    c0 c0Var22 = c0Var;
                                    StandardMatchGameFragment standardMatchGameFragment2 = standardMatchGameFragment;
                                    switch (i5) {
                                        case 0:
                                            String str5 = StandardMatchGameFragment.r;
                                            standardMatchGameFragment2.U().H(c0Var22);
                                            break;
                                        case 1:
                                            String str6 = StandardMatchGameFragment.r;
                                            standardMatchGameFragment2.U().H(c0Var22);
                                            break;
                                        case 2:
                                            String str7 = StandardMatchGameFragment.r;
                                            standardMatchGameFragment2.U().G(c0Var22);
                                            break;
                                        default:
                                            String str8 = StandardMatchGameFragment.r;
                                            standardMatchGameFragment2.U().G(c0Var22);
                                            break;
                                    }
                                }
                            }, gVar);
                            Intrinsics.checkNotNullExpressionValue(eVarF, "subscribe(...)");
                            standardMatchGameFragment.I(eVarF);
                        } else {
                            if (!(abstractC4352h instanceof C4351g)) {
                                throw new NoWhenBranchMatchedException();
                            }
                            final c0 c0Var2 = (c0) ((C4351g) abstractC4352h).a;
                            ((com.quizlet.features.match.viewmodel.f) standardMatchGameFragment.o.getValue()).C();
                            List list3 = standardMatchGameFragment.q;
                            if (list3 == null) {
                                Intrinsics.m("cards");
                                throw null;
                            }
                            io.reactivex.rxjava3.subjects.f fVarE = ((MatchCardView) list3.get(c0Var2.b)).e();
                            List list4 = standardMatchGameFragment.q;
                            if (list4 == null) {
                                Intrinsics.m("cards");
                                throw null;
                            }
                            List listJ2 = B.j(fVarE, ((MatchCardView) list4.get(c0Var2.c)).e());
                            Objects.requireNonNull(listJ2, "sources is null");
                            io.reactivex.rxjava3.internal.observers.e eVarF2 = new io.reactivex.rxjava3.internal.operators.completable.i(new io.reactivex.rxjava3.internal.operators.completable.c(listJ2, 0), gVar2, gVar2, bVar, new io.reactivex.rxjava3.functions.a() { // from class: com.quizlet.quizletandroid.ui.studymodes.match.fragment.r
                                @Override // io.reactivex.rxjava3.functions.a
                                public final void run() {
                                    c0 c0Var22 = c0Var2;
                                    StandardMatchGameFragment standardMatchGameFragment2 = standardMatchGameFragment;
                                    switch (i42) {
                                        case 0:
                                            String str5 = StandardMatchGameFragment.r;
                                            standardMatchGameFragment2.U().H(c0Var22);
                                            break;
                                        case 1:
                                            String str6 = StandardMatchGameFragment.r;
                                            standardMatchGameFragment2.U().H(c0Var22);
                                            break;
                                        case 2:
                                            String str7 = StandardMatchGameFragment.r;
                                            standardMatchGameFragment2.U().G(c0Var22);
                                            break;
                                        default:
                                            String str8 = StandardMatchGameFragment.r;
                                            standardMatchGameFragment2.U().G(c0Var22);
                                            break;
                                    }
                                }
                            }).f(new io.reactivex.rxjava3.functions.a() { // from class: com.quizlet.quizletandroid.ui.studymodes.match.fragment.r
                                @Override // io.reactivex.rxjava3.functions.a
                                public final void run() {
                                    c0 c0Var22 = c0Var2;
                                    StandardMatchGameFragment standardMatchGameFragment2 = standardMatchGameFragment;
                                    switch (i22) {
                                        case 0:
                                            String str5 = StandardMatchGameFragment.r;
                                            standardMatchGameFragment2.U().H(c0Var22);
                                            break;
                                        case 1:
                                            String str6 = StandardMatchGameFragment.r;
                                            standardMatchGameFragment2.U().H(c0Var22);
                                            break;
                                        case 2:
                                            String str7 = StandardMatchGameFragment.r;
                                            standardMatchGameFragment2.U().G(c0Var22);
                                            break;
                                        default:
                                            String str8 = StandardMatchGameFragment.r;
                                            standardMatchGameFragment2.U().G(c0Var22);
                                            break;
                                    }
                                }
                            }, gVar);
                            Intrinsics.checkNotNullExpressionValue(eVarF2, "subscribe(...)");
                            standardMatchGameFragment.I(eVarF2);
                        }
                        return Unit.a;
                }
            }
        }));
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onViewCreated(View view, Bundle bundle) {
        Intrinsics.checkNotNullParameter(view, "view");
        super.onViewCreated(view, bundle);
        A a = (A) J();
        List listJ = B.j(a.b, a.f, a.g, a.h, a.i, a.j, a.k, a.l, a.m, a.c, a.d, a.e);
        this.q = listJ;
        if (listJ == null) {
            Intrinsics.m("cards");
            throw null;
        }
        int i = 0;
        for (Object obj : listJ) {
            int i2 = i + 1;
            if (i < 0) {
                B.p();
                throw null;
            }
            MatchCardView matchCardView = (MatchCardView) obj;
            com.quizlet.qutils.image.loading.a aVar = this.j;
            if (aVar == null) {
                Intrinsics.m("imageLoader");
                throw null;
            }
            com.quizlet.quizletandroid.managers.audio.h hVar = this.k;
            if (hVar == null) {
                Intrinsics.m("audioPlayerManager");
                throw null;
            }
            io.ktor.client.plugins.api.d dVar = this.l;
            if (dVar == null) {
                Intrinsics.m("audioPlayFailureManager");
                throw null;
            }
            com.quizlet.richtext.rendering.c cVar = this.m;
            if (cVar == null) {
                Intrinsics.m("richTextRenderer");
                throw null;
            }
            com.quizlet.quizletandroid.util.f fVar = this.n;
            if (fVar == null) {
                Intrinsics.m("languageUtil");
                throw null;
            }
            matchCardView.g(aVar, hVar, dVar, cVar, fVar);
            matchCardView.setOnTouchListener(new c(this, i, 1));
            i = i2;
        }
    }
}

package com.quizlet.quizletandroid.ui.studymodes.match.fragment;

import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import androidx.camera.camera2.internal.T;
import com.google.android.gms.internal.mlkit_vision_barcode.N6;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.quizlet.features.match.data.AbstractC4352h;
import com.quizlet.features.match.data.C4345a;
import com.quizlet.features.match.data.C4346b;
import com.quizlet.features.match.data.C4347c;
import com.quizlet.features.match.data.C4349e;
import com.quizlet.features.match.data.C4350f;
import com.quizlet.features.match.data.C4351g;
import com.quizlet.features.match.data.C4356l;
import com.quizlet.features.match.data.C4358n;
import com.quizlet.features.match.data.C4360p;
import com.quizlet.features.match.data.C4364u;
import com.quizlet.features.setpage.viewmodel.C4430d;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.databinding.C4621z;
import com.quizlet.quizletandroid.ui.diagramming.DiagramView;
import com.quizlet.quizletandroid.ui.studymodes.match.view.MatchCardView;
import com.quizlet.studiablemodels.diagrams.DiagramData;
import io.reactivex.rxjava3.internal.operators.observable.W;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.collections.A;
import kotlin.collections.B;
import kotlin.collections.C;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;

@Metadata
/* loaded from: classes3.dex */
public final class DiagramMatchGameFragment extends Hilt_DiagramMatchGameFragment<C4621z> {
    public static final String t;
    public com.quizlet.qutils.image.loading.a j;
    public com.quizlet.quizletandroid.managers.audio.h k;
    public io.ktor.client.plugins.api.d l;
    public com.quizlet.richtext.rendering.c m;
    public com.quizlet.quizletandroid.util.f n;
    public io.reactivex.rxjava3.core.o o;
    public final com.quizlet.data.repository.folderwithcreatorinclass.e p = new com.quizlet.data.repository.folderwithcreatorinclass.e(K.a(com.quizlet.features.match.viewmodel.f.class), new d(this, 0), new d(this, 2), new d(this, 1));
    public final com.quizlet.data.repository.folderwithcreatorinclass.e q;
    public List r;
    public boolean s;

    static {
        Intrinsics.checkNotNullExpressionValue("DiagramMatchGameFragment", "getSimpleName(...)");
        t = "DiagramMatchGameFragment";
    }

    public DiagramMatchGameFragment() {
        com.quizlet.quizletandroid.ui.studymodes.assistant.settings.grading.a aVar = new com.quizlet.quizletandroid.ui.studymodes.assistant.settings.grading.a(this, 2);
        kotlin.k kVarA = kotlin.l.a(kotlin.m.c, new com.quizlet.login.recovery.forgotpassword.ui.e(new com.quizlet.login.recovery.forgotpassword.ui.e(this, 25), 26));
        this.q = new com.quizlet.data.repository.folderwithcreatorinclass.e(K.a(com.quizlet.features.match.viewmodel.d.class), new com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.i(kVarA, 4), new com.quizlet.quizletandroid.ui.activitycenter.fragments.h(this, kVarA, 17), new com.quizlet.quizletandroid.ui.activitycenter.fragments.h(aVar, kVarA, 16));
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final String N() {
        return t;
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final androidx.viewbinding.a O(LayoutInflater inflater, ViewGroup viewGroup) {
        Intrinsics.checkNotNullParameter(inflater, "inflater");
        View viewInflate = inflater.inflate(R.layout.fragment_match_game_diagram, viewGroup, false);
        int i = R.id.matchDiagramView;
        DiagramView diagramView = (DiagramView) AbstractC3375o2.c(R.id.matchDiagramView, viewInflate);
        if (diagramView != null) {
            i = R.id.matchSquare1;
            MatchCardView matchCardView = (MatchCardView) AbstractC3375o2.c(R.id.matchSquare1, viewInflate);
            if (matchCardView != null) {
                i = R.id.matchSquare2;
                MatchCardView matchCardView2 = (MatchCardView) AbstractC3375o2.c(R.id.matchSquare2, viewInflate);
                if (matchCardView2 != null) {
                    i = R.id.matchSquare3;
                    MatchCardView matchCardView3 = (MatchCardView) AbstractC3375o2.c(R.id.matchSquare3, viewInflate);
                    if (matchCardView3 != null) {
                        i = R.id.matchSquare4;
                        MatchCardView matchCardView4 = (MatchCardView) AbstractC3375o2.c(R.id.matchSquare4, viewInflate);
                        if (matchCardView4 != null) {
                            i = R.id.matchSquare5;
                            MatchCardView matchCardView5 = (MatchCardView) AbstractC3375o2.c(R.id.matchSquare5, viewInflate);
                            if (matchCardView5 != null) {
                                i = R.id.matchSquare6;
                                MatchCardView matchCardView6 = (MatchCardView) AbstractC3375o2.c(R.id.matchSquare6, viewInflate);
                                if (matchCardView6 != null) {
                                    C4621z c4621z = new C4621z((LinearLayout) viewInflate, diagramView, matchCardView, matchCardView2, matchCardView3, matchCardView4, matchCardView5, matchCardView6);
                                    Intrinsics.checkNotNullExpressionValue(c4621z, "inflate(...)");
                                    return c4621z;
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
        List list2 = this.r;
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

    public final void U(List list) {
        ArrayList arrayList = new ArrayList();
        for (Object obj : list) {
            if (!(((C4349e) obj).a instanceof C4356l)) {
                arrayList.add(obj);
            }
        }
        ArrayList arrayList2 = new ArrayList(C.q(arrayList, 10));
        Iterator it2 = arrayList.iterator();
        while (it2.hasNext()) {
            arrayList2.add(Long.valueOf(((C4349e) it2.next()).b));
        }
        boolean zIsEmpty = arrayList2.isEmpty();
        Collection collectionB = arrayList2;
        if (zIsEmpty) {
            collectionB = A.b(-1L);
        }
        Collection termIds = collectionB;
        DiagramView diagramViewV = V();
        diagramViewV.getClass();
        Intrinsics.checkNotNullParameter(termIds, "termIds");
        com.quizlet.quizletandroid.ui.diagramming.j presenter = diagramViewV.getPresenter();
        presenter.getClass();
        Intrinsics.checkNotNullParameter(termIds, "termIds");
        String str = String.format("showTerms('%s');", Arrays.copyOf(new Object[]{CollectionsKt.S(termIds, ",", null, null, null, 62)}, 1));
        Intrinsics.checkNotNullExpressionValue(str, "format(...)");
        presenter.a(str);
        Iterator it3 = list.iterator();
        while (it3.hasNext()) {
            C4349e c4349e = (C4349e) it3.next();
            N6 n6 = c4349e.a;
            if (n6 instanceof C4358n) {
                boolean z = ((C4358n) n6).a;
                long j = c4349e.b;
                if (z) {
                    com.quizlet.quizletandroid.ui.diagramming.j presenter2 = V().getPresenter();
                    presenter2.e.add(Long.valueOf(j));
                    String str2 = String.format("onSelectTerm('%d');", Arrays.copyOf(new Object[]{Long.valueOf(j)}, 1));
                    Intrinsics.checkNotNullExpressionValue(str2, "format(...)");
                    presenter2.a(str2);
                } else {
                    com.quizlet.quizletandroid.ui.diagramming.j presenter3 = V().getPresenter();
                    presenter3.e.remove(Long.valueOf(j));
                    String str3 = String.format("onDeselectTerm('%d');", Arrays.copyOf(new Object[]{Long.valueOf(j)}, 1));
                    Intrinsics.checkNotNullExpressionValue(str3, "format(...)");
                    presenter3.a(str3);
                }
            }
        }
    }

    public final DiagramView V() {
        DiagramView matchDiagramView = ((C4621z) J()).b;
        Intrinsics.checkNotNullExpressionValue(matchDiagramView, "matchDiagramView");
        return matchDiagramView;
    }

    public final com.quizlet.features.match.viewmodel.d W() {
        return (com.quizlet.features.match.viewmodel.d) this.q.getValue();
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        final int i = 0;
        W().e.f(this, new com.quizlet.explanations.feedback.ui.fragments.c(23, new Function1(this) { // from class: com.quizlet.quizletandroid.ui.studymodes.match.fragment.b
            public final /* synthetic */ DiagramMatchGameFragment b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object obj) {
                final int i2 = 0;
                final int i3 = 1;
                final DiagramMatchGameFragment diagramMatchGameFragment = this.b;
                switch (i) {
                    case 0:
                        String str = DiagramMatchGameFragment.t;
                        ((com.quizlet.features.match.viewmodel.f) diagramMatchGameFragment.p.getValue()).B();
                        return Unit.a;
                    case 1:
                        String str2 = DiagramMatchGameFragment.t;
                        com.quizlet.features.match.viewmodel.f fVar = (com.quizlet.features.match.viewmodel.f) diagramMatchGameFragment.p.getValue();
                        com.quizlet.features.match.studyengine.e eVar = (com.quizlet.features.match.studyengine.e) fVar.c;
                        eVar.b();
                        eVar.g = System.currentTimeMillis();
                        fVar.e.l(C4360p.a);
                        return Unit.a;
                    case 2:
                        com.quizlet.features.match.data.C c = (com.quizlet.features.match.data.C) obj;
                        String str3 = DiagramMatchGameFragment.t;
                        if (c instanceof com.quizlet.features.match.data.A) {
                            C4346b c4346b = (C4346b) ((com.quizlet.features.match.data.A) c).a;
                            diagramMatchGameFragment.T(c4346b.c);
                            boolean z = diagramMatchGameFragment.s;
                            ArrayList arrayList = c4346b.b;
                            if (z) {
                                diagramMatchGameFragment.U(arrayList);
                            } else {
                                io.reactivex.rxjava3.core.i termClicks = diagramMatchGameFragment.V().getTermClicks();
                                io.reactivex.rxjava3.core.o oVar = diagramMatchGameFragment.o;
                                if (oVar == null) {
                                    Intrinsics.m("mainThreadScheduler");
                                    throw null;
                                }
                                W wS = termClicks.s(oVar);
                                com.quizlet.quizletandroid.ui.setpage.terms.c cVar = new com.quizlet.quizletandroid.ui.setpage.terms.c(diagramMatchGameFragment.W(), 4);
                                timber.log.a aVar = timber.log.c.a;
                                io.reactivex.rxjava3.disposables.b bVarU = wS.u(cVar, new com.quizlet.billing.manager.d(aVar, 15), io.reactivex.rxjava3.internal.functions.d.c);
                                Intrinsics.checkNotNullExpressionValue(bVarU, "subscribe(...)");
                                diagramMatchGameFragment.G(bVarU);
                                DiagramView diagramViewV = diagramMatchGameFragment.V();
                                com.quizlet.diagrams.b[] diagramLoadingConfigurations = new com.quizlet.diagrams.b[0];
                                diagramViewV.getClass();
                                DiagramData data = c4346b.a;
                                Intrinsics.checkNotNullParameter(data, "data");
                                Intrinsics.checkNotNullParameter(diagramLoadingConfigurations, "diagramLoadingConfigurations");
                                io.reactivex.rxjava3.internal.operators.completable.c cVar2 = new io.reactivex.rxjava3.internal.operators.completable.c(new T(diagramViewV, data, diagramLoadingConfigurations, 24), 1);
                                Intrinsics.checkNotNullExpressionValue(cVar2, "create(...)");
                                io.reactivex.rxjava3.core.o oVar2 = diagramMatchGameFragment.o;
                                if (oVar2 == null) {
                                    Intrinsics.m("mainThreadScheduler");
                                    throw null;
                                }
                                io.reactivex.rxjava3.internal.observers.e eVarF = new io.reactivex.rxjava3.internal.operators.completable.h(cVar2, oVar2, 0).f(new C4430d(5, diagramMatchGameFragment, arrayList), new com.quizlet.billing.manager.d(aVar, 16));
                                Intrinsics.checkNotNullExpressionValue(eVarF, "subscribe(...)");
                                diagramMatchGameFragment.G(eVarF);
                            }
                        } else {
                            if (!Intrinsics.b(c, com.quizlet.features.match.data.B.a)) {
                                throw new NoWhenBranchMatchedException();
                            }
                            kotlin.collections.K k = kotlin.collections.K.a;
                            diagramMatchGameFragment.T(k);
                            if (diagramMatchGameFragment.s) {
                                diagramMatchGameFragment.U(k);
                            }
                            com.quizlet.features.match.viewmodel.f fVar2 = (com.quizlet.features.match.viewmodel.f) diagramMatchGameFragment.p.getValue();
                            com.quizlet.features.match.studyengine.e eVar2 = (com.quizlet.features.match.studyengine.e) fVar2.c;
                            fVar2.d.o(new C4364u(eVar2.g, eVar2.h));
                        }
                        return Unit.a;
                    default:
                        AbstractC4352h abstractC4352h = (AbstractC4352h) obj;
                        String str4 = DiagramMatchGameFragment.t;
                        boolean z2 = abstractC4352h instanceof C4350f;
                        com.quizlet.infra.legacysyncengine.net.request.g gVar = io.reactivex.rxjava3.internal.functions.d.e;
                        io.reactivex.rxjava3.internal.functions.b bVar = io.reactivex.rxjava3.internal.functions.d.c;
                        com.quizlet.infra.legacysyncengine.net.request.g gVar2 = io.reactivex.rxjava3.internal.functions.d.d;
                        if (z2) {
                            final C4347c c4347c = (C4347c) ((C4350f) abstractC4352h).a;
                            com.quizlet.quizletandroid.ui.diagramming.j presenter = diagramMatchGameFragment.V().getPresenter();
                            presenter.getClass();
                            String str5 = String.format("onCorrectTerm('%d');", Arrays.copyOf(new Object[]{Long.valueOf(c4347c.b)}, 1));
                            Intrinsics.checkNotNullExpressionValue(str5, "format(...)");
                            presenter.a(str5);
                            List list = diagramMatchGameFragment.r;
                            if (list == null) {
                                Intrinsics.m("cards");
                                throw null;
                            }
                            final int i4 = 3;
                            io.reactivex.rxjava3.internal.observers.e eVarF2 = new io.reactivex.rxjava3.internal.operators.completable.i(((MatchCardView) list.get(c4347c.c)).d(), gVar2, gVar2, bVar, new io.reactivex.rxjava3.functions.a() { // from class: com.quizlet.quizletandroid.ui.studymodes.match.fragment.a
                                @Override // io.reactivex.rxjava3.functions.a
                                public final void run() {
                                    C4347c c4347c2 = c4347c;
                                    DiagramMatchGameFragment diagramMatchGameFragment2 = diagramMatchGameFragment;
                                    switch (i4) {
                                        case 0:
                                            String str6 = DiagramMatchGameFragment.t;
                                            diagramMatchGameFragment2.W().G(c4347c2);
                                            break;
                                        case 1:
                                            String str7 = DiagramMatchGameFragment.t;
                                            diagramMatchGameFragment2.W().H(c4347c2);
                                            break;
                                        case 2:
                                            String str8 = DiagramMatchGameFragment.t;
                                            diagramMatchGameFragment2.W().H(c4347c2);
                                            break;
                                        default:
                                            String str9 = DiagramMatchGameFragment.t;
                                            diagramMatchGameFragment2.W().G(c4347c2);
                                            break;
                                    }
                                }
                            }).f(new io.reactivex.rxjava3.functions.a() { // from class: com.quizlet.quizletandroid.ui.studymodes.match.fragment.a
                                @Override // io.reactivex.rxjava3.functions.a
                                public final void run() {
                                    C4347c c4347c2 = c4347c;
                                    DiagramMatchGameFragment diagramMatchGameFragment2 = diagramMatchGameFragment;
                                    switch (i2) {
                                        case 0:
                                            String str6 = DiagramMatchGameFragment.t;
                                            diagramMatchGameFragment2.W().G(c4347c2);
                                            break;
                                        case 1:
                                            String str7 = DiagramMatchGameFragment.t;
                                            diagramMatchGameFragment2.W().H(c4347c2);
                                            break;
                                        case 2:
                                            String str8 = DiagramMatchGameFragment.t;
                                            diagramMatchGameFragment2.W().H(c4347c2);
                                            break;
                                        default:
                                            String str9 = DiagramMatchGameFragment.t;
                                            diagramMatchGameFragment2.W().G(c4347c2);
                                            break;
                                    }
                                }
                            }, gVar);
                            Intrinsics.checkNotNullExpressionValue(eVarF2, "subscribe(...)");
                            diagramMatchGameFragment.I(eVarF2);
                        } else {
                            if (!(abstractC4352h instanceof C4351g)) {
                                throw new NoWhenBranchMatchedException();
                            }
                            final C4347c c4347c2 = (C4347c) ((C4351g) abstractC4352h).a;
                            ((com.quizlet.features.match.viewmodel.f) diagramMatchGameFragment.p.getValue()).C();
                            com.quizlet.quizletandroid.ui.diagramming.j presenter2 = diagramMatchGameFragment.V().getPresenter();
                            presenter2.getClass();
                            String str6 = String.format("onIncorrectTerm('%d');", Arrays.copyOf(new Object[]{Long.valueOf(c4347c2.b)}, 1));
                            Intrinsics.checkNotNullExpressionValue(str6, "format(...)");
                            presenter2.a(str6);
                            List list2 = diagramMatchGameFragment.r;
                            if (list2 == null) {
                                Intrinsics.m("cards");
                                throw null;
                            }
                            io.reactivex.rxjava3.internal.operators.completable.i iVar = new io.reactivex.rxjava3.internal.operators.completable.i(((MatchCardView) list2.get(c4347c2.c)).e(), gVar2, gVar2, bVar, new io.reactivex.rxjava3.functions.a() { // from class: com.quizlet.quizletandroid.ui.studymodes.match.fragment.a
                                @Override // io.reactivex.rxjava3.functions.a
                                public final void run() {
                                    C4347c c4347c22 = c4347c2;
                                    DiagramMatchGameFragment diagramMatchGameFragment2 = diagramMatchGameFragment;
                                    switch (i3) {
                                        case 0:
                                            String str62 = DiagramMatchGameFragment.t;
                                            diagramMatchGameFragment2.W().G(c4347c22);
                                            break;
                                        case 1:
                                            String str7 = DiagramMatchGameFragment.t;
                                            diagramMatchGameFragment2.W().H(c4347c22);
                                            break;
                                        case 2:
                                            String str8 = DiagramMatchGameFragment.t;
                                            diagramMatchGameFragment2.W().H(c4347c22);
                                            break;
                                        default:
                                            String str9 = DiagramMatchGameFragment.t;
                                            diagramMatchGameFragment2.W().G(c4347c22);
                                            break;
                                    }
                                }
                            });
                            final int i5 = 2;
                            io.reactivex.rxjava3.internal.observers.e eVarF3 = iVar.f(new io.reactivex.rxjava3.functions.a() { // from class: com.quizlet.quizletandroid.ui.studymodes.match.fragment.a
                                @Override // io.reactivex.rxjava3.functions.a
                                public final void run() {
                                    C4347c c4347c22 = c4347c2;
                                    DiagramMatchGameFragment diagramMatchGameFragment2 = diagramMatchGameFragment;
                                    switch (i5) {
                                        case 0:
                                            String str62 = DiagramMatchGameFragment.t;
                                            diagramMatchGameFragment2.W().G(c4347c22);
                                            break;
                                        case 1:
                                            String str7 = DiagramMatchGameFragment.t;
                                            diagramMatchGameFragment2.W().H(c4347c22);
                                            break;
                                        case 2:
                                            String str8 = DiagramMatchGameFragment.t;
                                            diagramMatchGameFragment2.W().H(c4347c22);
                                            break;
                                        default:
                                            String str9 = DiagramMatchGameFragment.t;
                                            diagramMatchGameFragment2.W().G(c4347c22);
                                            break;
                                    }
                                }
                            }, gVar);
                            Intrinsics.checkNotNullExpressionValue(eVarF3, "subscribe(...)");
                            diagramMatchGameFragment.I(eVarF3);
                        }
                        return Unit.a;
                }
            }
        }));
        final int i2 = 1;
        W().f.f(this, new com.quizlet.explanations.feedback.ui.fragments.c(23, new Function1(this) { // from class: com.quizlet.quizletandroid.ui.studymodes.match.fragment.b
            public final /* synthetic */ DiagramMatchGameFragment b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object obj) {
                final int i22 = 0;
                final int i3 = 1;
                final DiagramMatchGameFragment diagramMatchGameFragment = this.b;
                switch (i2) {
                    case 0:
                        String str = DiagramMatchGameFragment.t;
                        ((com.quizlet.features.match.viewmodel.f) diagramMatchGameFragment.p.getValue()).B();
                        return Unit.a;
                    case 1:
                        String str2 = DiagramMatchGameFragment.t;
                        com.quizlet.features.match.viewmodel.f fVar = (com.quizlet.features.match.viewmodel.f) diagramMatchGameFragment.p.getValue();
                        com.quizlet.features.match.studyengine.e eVar = (com.quizlet.features.match.studyengine.e) fVar.c;
                        eVar.b();
                        eVar.g = System.currentTimeMillis();
                        fVar.e.l(C4360p.a);
                        return Unit.a;
                    case 2:
                        com.quizlet.features.match.data.C c = (com.quizlet.features.match.data.C) obj;
                        String str3 = DiagramMatchGameFragment.t;
                        if (c instanceof com.quizlet.features.match.data.A) {
                            C4346b c4346b = (C4346b) ((com.quizlet.features.match.data.A) c).a;
                            diagramMatchGameFragment.T(c4346b.c);
                            boolean z = diagramMatchGameFragment.s;
                            ArrayList arrayList = c4346b.b;
                            if (z) {
                                diagramMatchGameFragment.U(arrayList);
                            } else {
                                io.reactivex.rxjava3.core.i termClicks = diagramMatchGameFragment.V().getTermClicks();
                                io.reactivex.rxjava3.core.o oVar = diagramMatchGameFragment.o;
                                if (oVar == null) {
                                    Intrinsics.m("mainThreadScheduler");
                                    throw null;
                                }
                                W wS = termClicks.s(oVar);
                                com.quizlet.quizletandroid.ui.setpage.terms.c cVar = new com.quizlet.quizletandroid.ui.setpage.terms.c(diagramMatchGameFragment.W(), 4);
                                timber.log.a aVar = timber.log.c.a;
                                io.reactivex.rxjava3.disposables.b bVarU = wS.u(cVar, new com.quizlet.billing.manager.d(aVar, 15), io.reactivex.rxjava3.internal.functions.d.c);
                                Intrinsics.checkNotNullExpressionValue(bVarU, "subscribe(...)");
                                diagramMatchGameFragment.G(bVarU);
                                DiagramView diagramViewV = diagramMatchGameFragment.V();
                                com.quizlet.diagrams.b[] diagramLoadingConfigurations = new com.quizlet.diagrams.b[0];
                                diagramViewV.getClass();
                                DiagramData data = c4346b.a;
                                Intrinsics.checkNotNullParameter(data, "data");
                                Intrinsics.checkNotNullParameter(diagramLoadingConfigurations, "diagramLoadingConfigurations");
                                io.reactivex.rxjava3.internal.operators.completable.c cVar2 = new io.reactivex.rxjava3.internal.operators.completable.c(new T(diagramViewV, data, diagramLoadingConfigurations, 24), 1);
                                Intrinsics.checkNotNullExpressionValue(cVar2, "create(...)");
                                io.reactivex.rxjava3.core.o oVar2 = diagramMatchGameFragment.o;
                                if (oVar2 == null) {
                                    Intrinsics.m("mainThreadScheduler");
                                    throw null;
                                }
                                io.reactivex.rxjava3.internal.observers.e eVarF = new io.reactivex.rxjava3.internal.operators.completable.h(cVar2, oVar2, 0).f(new C4430d(5, diagramMatchGameFragment, arrayList), new com.quizlet.billing.manager.d(aVar, 16));
                                Intrinsics.checkNotNullExpressionValue(eVarF, "subscribe(...)");
                                diagramMatchGameFragment.G(eVarF);
                            }
                        } else {
                            if (!Intrinsics.b(c, com.quizlet.features.match.data.B.a)) {
                                throw new NoWhenBranchMatchedException();
                            }
                            kotlin.collections.K k = kotlin.collections.K.a;
                            diagramMatchGameFragment.T(k);
                            if (diagramMatchGameFragment.s) {
                                diagramMatchGameFragment.U(k);
                            }
                            com.quizlet.features.match.viewmodel.f fVar2 = (com.quizlet.features.match.viewmodel.f) diagramMatchGameFragment.p.getValue();
                            com.quizlet.features.match.studyengine.e eVar2 = (com.quizlet.features.match.studyengine.e) fVar2.c;
                            fVar2.d.o(new C4364u(eVar2.g, eVar2.h));
                        }
                        return Unit.a;
                    default:
                        AbstractC4352h abstractC4352h = (AbstractC4352h) obj;
                        String str4 = DiagramMatchGameFragment.t;
                        boolean z2 = abstractC4352h instanceof C4350f;
                        com.quizlet.infra.legacysyncengine.net.request.g gVar = io.reactivex.rxjava3.internal.functions.d.e;
                        io.reactivex.rxjava3.internal.functions.b bVar = io.reactivex.rxjava3.internal.functions.d.c;
                        com.quizlet.infra.legacysyncengine.net.request.g gVar2 = io.reactivex.rxjava3.internal.functions.d.d;
                        if (z2) {
                            final C4347c c4347c = (C4347c) ((C4350f) abstractC4352h).a;
                            com.quizlet.quizletandroid.ui.diagramming.j presenter = diagramMatchGameFragment.V().getPresenter();
                            presenter.getClass();
                            String str5 = String.format("onCorrectTerm('%d');", Arrays.copyOf(new Object[]{Long.valueOf(c4347c.b)}, 1));
                            Intrinsics.checkNotNullExpressionValue(str5, "format(...)");
                            presenter.a(str5);
                            List list = diagramMatchGameFragment.r;
                            if (list == null) {
                                Intrinsics.m("cards");
                                throw null;
                            }
                            final int i4 = 3;
                            io.reactivex.rxjava3.internal.observers.e eVarF2 = new io.reactivex.rxjava3.internal.operators.completable.i(((MatchCardView) list.get(c4347c.c)).d(), gVar2, gVar2, bVar, new io.reactivex.rxjava3.functions.a() { // from class: com.quizlet.quizletandroid.ui.studymodes.match.fragment.a
                                @Override // io.reactivex.rxjava3.functions.a
                                public final void run() {
                                    C4347c c4347c22 = c4347c;
                                    DiagramMatchGameFragment diagramMatchGameFragment2 = diagramMatchGameFragment;
                                    switch (i4) {
                                        case 0:
                                            String str62 = DiagramMatchGameFragment.t;
                                            diagramMatchGameFragment2.W().G(c4347c22);
                                            break;
                                        case 1:
                                            String str7 = DiagramMatchGameFragment.t;
                                            diagramMatchGameFragment2.W().H(c4347c22);
                                            break;
                                        case 2:
                                            String str8 = DiagramMatchGameFragment.t;
                                            diagramMatchGameFragment2.W().H(c4347c22);
                                            break;
                                        default:
                                            String str9 = DiagramMatchGameFragment.t;
                                            diagramMatchGameFragment2.W().G(c4347c22);
                                            break;
                                    }
                                }
                            }).f(new io.reactivex.rxjava3.functions.a() { // from class: com.quizlet.quizletandroid.ui.studymodes.match.fragment.a
                                @Override // io.reactivex.rxjava3.functions.a
                                public final void run() {
                                    C4347c c4347c22 = c4347c;
                                    DiagramMatchGameFragment diagramMatchGameFragment2 = diagramMatchGameFragment;
                                    switch (i22) {
                                        case 0:
                                            String str62 = DiagramMatchGameFragment.t;
                                            diagramMatchGameFragment2.W().G(c4347c22);
                                            break;
                                        case 1:
                                            String str7 = DiagramMatchGameFragment.t;
                                            diagramMatchGameFragment2.W().H(c4347c22);
                                            break;
                                        case 2:
                                            String str8 = DiagramMatchGameFragment.t;
                                            diagramMatchGameFragment2.W().H(c4347c22);
                                            break;
                                        default:
                                            String str9 = DiagramMatchGameFragment.t;
                                            diagramMatchGameFragment2.W().G(c4347c22);
                                            break;
                                    }
                                }
                            }, gVar);
                            Intrinsics.checkNotNullExpressionValue(eVarF2, "subscribe(...)");
                            diagramMatchGameFragment.I(eVarF2);
                        } else {
                            if (!(abstractC4352h instanceof C4351g)) {
                                throw new NoWhenBranchMatchedException();
                            }
                            final C4347c c4347c2 = (C4347c) ((C4351g) abstractC4352h).a;
                            ((com.quizlet.features.match.viewmodel.f) diagramMatchGameFragment.p.getValue()).C();
                            com.quizlet.quizletandroid.ui.diagramming.j presenter2 = diagramMatchGameFragment.V().getPresenter();
                            presenter2.getClass();
                            String str6 = String.format("onIncorrectTerm('%d');", Arrays.copyOf(new Object[]{Long.valueOf(c4347c2.b)}, 1));
                            Intrinsics.checkNotNullExpressionValue(str6, "format(...)");
                            presenter2.a(str6);
                            List list2 = diagramMatchGameFragment.r;
                            if (list2 == null) {
                                Intrinsics.m("cards");
                                throw null;
                            }
                            io.reactivex.rxjava3.internal.operators.completable.i iVar = new io.reactivex.rxjava3.internal.operators.completable.i(((MatchCardView) list2.get(c4347c2.c)).e(), gVar2, gVar2, bVar, new io.reactivex.rxjava3.functions.a() { // from class: com.quizlet.quizletandroid.ui.studymodes.match.fragment.a
                                @Override // io.reactivex.rxjava3.functions.a
                                public final void run() {
                                    C4347c c4347c22 = c4347c2;
                                    DiagramMatchGameFragment diagramMatchGameFragment2 = diagramMatchGameFragment;
                                    switch (i3) {
                                        case 0:
                                            String str62 = DiagramMatchGameFragment.t;
                                            diagramMatchGameFragment2.W().G(c4347c22);
                                            break;
                                        case 1:
                                            String str7 = DiagramMatchGameFragment.t;
                                            diagramMatchGameFragment2.W().H(c4347c22);
                                            break;
                                        case 2:
                                            String str8 = DiagramMatchGameFragment.t;
                                            diagramMatchGameFragment2.W().H(c4347c22);
                                            break;
                                        default:
                                            String str9 = DiagramMatchGameFragment.t;
                                            diagramMatchGameFragment2.W().G(c4347c22);
                                            break;
                                    }
                                }
                            });
                            final int i5 = 2;
                            io.reactivex.rxjava3.internal.observers.e eVarF3 = iVar.f(new io.reactivex.rxjava3.functions.a() { // from class: com.quizlet.quizletandroid.ui.studymodes.match.fragment.a
                                @Override // io.reactivex.rxjava3.functions.a
                                public final void run() {
                                    C4347c c4347c22 = c4347c2;
                                    DiagramMatchGameFragment diagramMatchGameFragment2 = diagramMatchGameFragment;
                                    switch (i5) {
                                        case 0:
                                            String str62 = DiagramMatchGameFragment.t;
                                            diagramMatchGameFragment2.W().G(c4347c22);
                                            break;
                                        case 1:
                                            String str7 = DiagramMatchGameFragment.t;
                                            diagramMatchGameFragment2.W().H(c4347c22);
                                            break;
                                        case 2:
                                            String str8 = DiagramMatchGameFragment.t;
                                            diagramMatchGameFragment2.W().H(c4347c22);
                                            break;
                                        default:
                                            String str9 = DiagramMatchGameFragment.t;
                                            diagramMatchGameFragment2.W().G(c4347c22);
                                            break;
                                    }
                                }
                            }, gVar);
                            Intrinsics.checkNotNullExpressionValue(eVarF3, "subscribe(...)");
                            diagramMatchGameFragment.I(eVarF3);
                        }
                        return Unit.a;
                }
            }
        }));
        final int i3 = 2;
        W().g.f(this, new com.quizlet.explanations.feedback.ui.fragments.c(23, new Function1(this) { // from class: com.quizlet.quizletandroid.ui.studymodes.match.fragment.b
            public final /* synthetic */ DiagramMatchGameFragment b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object obj) {
                final int i22 = 0;
                final int i32 = 1;
                final DiagramMatchGameFragment diagramMatchGameFragment = this.b;
                switch (i3) {
                    case 0:
                        String str = DiagramMatchGameFragment.t;
                        ((com.quizlet.features.match.viewmodel.f) diagramMatchGameFragment.p.getValue()).B();
                        return Unit.a;
                    case 1:
                        String str2 = DiagramMatchGameFragment.t;
                        com.quizlet.features.match.viewmodel.f fVar = (com.quizlet.features.match.viewmodel.f) diagramMatchGameFragment.p.getValue();
                        com.quizlet.features.match.studyengine.e eVar = (com.quizlet.features.match.studyengine.e) fVar.c;
                        eVar.b();
                        eVar.g = System.currentTimeMillis();
                        fVar.e.l(C4360p.a);
                        return Unit.a;
                    case 2:
                        com.quizlet.features.match.data.C c = (com.quizlet.features.match.data.C) obj;
                        String str3 = DiagramMatchGameFragment.t;
                        if (c instanceof com.quizlet.features.match.data.A) {
                            C4346b c4346b = (C4346b) ((com.quizlet.features.match.data.A) c).a;
                            diagramMatchGameFragment.T(c4346b.c);
                            boolean z = diagramMatchGameFragment.s;
                            ArrayList arrayList = c4346b.b;
                            if (z) {
                                diagramMatchGameFragment.U(arrayList);
                            } else {
                                io.reactivex.rxjava3.core.i termClicks = diagramMatchGameFragment.V().getTermClicks();
                                io.reactivex.rxjava3.core.o oVar = diagramMatchGameFragment.o;
                                if (oVar == null) {
                                    Intrinsics.m("mainThreadScheduler");
                                    throw null;
                                }
                                W wS = termClicks.s(oVar);
                                com.quizlet.quizletandroid.ui.setpage.terms.c cVar = new com.quizlet.quizletandroid.ui.setpage.terms.c(diagramMatchGameFragment.W(), 4);
                                timber.log.a aVar = timber.log.c.a;
                                io.reactivex.rxjava3.disposables.b bVarU = wS.u(cVar, new com.quizlet.billing.manager.d(aVar, 15), io.reactivex.rxjava3.internal.functions.d.c);
                                Intrinsics.checkNotNullExpressionValue(bVarU, "subscribe(...)");
                                diagramMatchGameFragment.G(bVarU);
                                DiagramView diagramViewV = diagramMatchGameFragment.V();
                                com.quizlet.diagrams.b[] diagramLoadingConfigurations = new com.quizlet.diagrams.b[0];
                                diagramViewV.getClass();
                                DiagramData data = c4346b.a;
                                Intrinsics.checkNotNullParameter(data, "data");
                                Intrinsics.checkNotNullParameter(diagramLoadingConfigurations, "diagramLoadingConfigurations");
                                io.reactivex.rxjava3.internal.operators.completable.c cVar2 = new io.reactivex.rxjava3.internal.operators.completable.c(new T(diagramViewV, data, diagramLoadingConfigurations, 24), 1);
                                Intrinsics.checkNotNullExpressionValue(cVar2, "create(...)");
                                io.reactivex.rxjava3.core.o oVar2 = diagramMatchGameFragment.o;
                                if (oVar2 == null) {
                                    Intrinsics.m("mainThreadScheduler");
                                    throw null;
                                }
                                io.reactivex.rxjava3.internal.observers.e eVarF = new io.reactivex.rxjava3.internal.operators.completable.h(cVar2, oVar2, 0).f(new C4430d(5, diagramMatchGameFragment, arrayList), new com.quizlet.billing.manager.d(aVar, 16));
                                Intrinsics.checkNotNullExpressionValue(eVarF, "subscribe(...)");
                                diagramMatchGameFragment.G(eVarF);
                            }
                        } else {
                            if (!Intrinsics.b(c, com.quizlet.features.match.data.B.a)) {
                                throw new NoWhenBranchMatchedException();
                            }
                            kotlin.collections.K k = kotlin.collections.K.a;
                            diagramMatchGameFragment.T(k);
                            if (diagramMatchGameFragment.s) {
                                diagramMatchGameFragment.U(k);
                            }
                            com.quizlet.features.match.viewmodel.f fVar2 = (com.quizlet.features.match.viewmodel.f) diagramMatchGameFragment.p.getValue();
                            com.quizlet.features.match.studyengine.e eVar2 = (com.quizlet.features.match.studyengine.e) fVar2.c;
                            fVar2.d.o(new C4364u(eVar2.g, eVar2.h));
                        }
                        return Unit.a;
                    default:
                        AbstractC4352h abstractC4352h = (AbstractC4352h) obj;
                        String str4 = DiagramMatchGameFragment.t;
                        boolean z2 = abstractC4352h instanceof C4350f;
                        com.quizlet.infra.legacysyncengine.net.request.g gVar = io.reactivex.rxjava3.internal.functions.d.e;
                        io.reactivex.rxjava3.internal.functions.b bVar = io.reactivex.rxjava3.internal.functions.d.c;
                        com.quizlet.infra.legacysyncengine.net.request.g gVar2 = io.reactivex.rxjava3.internal.functions.d.d;
                        if (z2) {
                            final C4347c c4347c = (C4347c) ((C4350f) abstractC4352h).a;
                            com.quizlet.quizletandroid.ui.diagramming.j presenter = diagramMatchGameFragment.V().getPresenter();
                            presenter.getClass();
                            String str5 = String.format("onCorrectTerm('%d');", Arrays.copyOf(new Object[]{Long.valueOf(c4347c.b)}, 1));
                            Intrinsics.checkNotNullExpressionValue(str5, "format(...)");
                            presenter.a(str5);
                            List list = diagramMatchGameFragment.r;
                            if (list == null) {
                                Intrinsics.m("cards");
                                throw null;
                            }
                            final int i4 = 3;
                            io.reactivex.rxjava3.internal.observers.e eVarF2 = new io.reactivex.rxjava3.internal.operators.completable.i(((MatchCardView) list.get(c4347c.c)).d(), gVar2, gVar2, bVar, new io.reactivex.rxjava3.functions.a() { // from class: com.quizlet.quizletandroid.ui.studymodes.match.fragment.a
                                @Override // io.reactivex.rxjava3.functions.a
                                public final void run() {
                                    C4347c c4347c22 = c4347c;
                                    DiagramMatchGameFragment diagramMatchGameFragment2 = diagramMatchGameFragment;
                                    switch (i4) {
                                        case 0:
                                            String str62 = DiagramMatchGameFragment.t;
                                            diagramMatchGameFragment2.W().G(c4347c22);
                                            break;
                                        case 1:
                                            String str7 = DiagramMatchGameFragment.t;
                                            diagramMatchGameFragment2.W().H(c4347c22);
                                            break;
                                        case 2:
                                            String str8 = DiagramMatchGameFragment.t;
                                            diagramMatchGameFragment2.W().H(c4347c22);
                                            break;
                                        default:
                                            String str9 = DiagramMatchGameFragment.t;
                                            diagramMatchGameFragment2.W().G(c4347c22);
                                            break;
                                    }
                                }
                            }).f(new io.reactivex.rxjava3.functions.a() { // from class: com.quizlet.quizletandroid.ui.studymodes.match.fragment.a
                                @Override // io.reactivex.rxjava3.functions.a
                                public final void run() {
                                    C4347c c4347c22 = c4347c;
                                    DiagramMatchGameFragment diagramMatchGameFragment2 = diagramMatchGameFragment;
                                    switch (i22) {
                                        case 0:
                                            String str62 = DiagramMatchGameFragment.t;
                                            diagramMatchGameFragment2.W().G(c4347c22);
                                            break;
                                        case 1:
                                            String str7 = DiagramMatchGameFragment.t;
                                            diagramMatchGameFragment2.W().H(c4347c22);
                                            break;
                                        case 2:
                                            String str8 = DiagramMatchGameFragment.t;
                                            diagramMatchGameFragment2.W().H(c4347c22);
                                            break;
                                        default:
                                            String str9 = DiagramMatchGameFragment.t;
                                            diagramMatchGameFragment2.W().G(c4347c22);
                                            break;
                                    }
                                }
                            }, gVar);
                            Intrinsics.checkNotNullExpressionValue(eVarF2, "subscribe(...)");
                            diagramMatchGameFragment.I(eVarF2);
                        } else {
                            if (!(abstractC4352h instanceof C4351g)) {
                                throw new NoWhenBranchMatchedException();
                            }
                            final C4347c c4347c2 = (C4347c) ((C4351g) abstractC4352h).a;
                            ((com.quizlet.features.match.viewmodel.f) diagramMatchGameFragment.p.getValue()).C();
                            com.quizlet.quizletandroid.ui.diagramming.j presenter2 = diagramMatchGameFragment.V().getPresenter();
                            presenter2.getClass();
                            String str6 = String.format("onIncorrectTerm('%d');", Arrays.copyOf(new Object[]{Long.valueOf(c4347c2.b)}, 1));
                            Intrinsics.checkNotNullExpressionValue(str6, "format(...)");
                            presenter2.a(str6);
                            List list2 = diagramMatchGameFragment.r;
                            if (list2 == null) {
                                Intrinsics.m("cards");
                                throw null;
                            }
                            io.reactivex.rxjava3.internal.operators.completable.i iVar = new io.reactivex.rxjava3.internal.operators.completable.i(((MatchCardView) list2.get(c4347c2.c)).e(), gVar2, gVar2, bVar, new io.reactivex.rxjava3.functions.a() { // from class: com.quizlet.quizletandroid.ui.studymodes.match.fragment.a
                                @Override // io.reactivex.rxjava3.functions.a
                                public final void run() {
                                    C4347c c4347c22 = c4347c2;
                                    DiagramMatchGameFragment diagramMatchGameFragment2 = diagramMatchGameFragment;
                                    switch (i32) {
                                        case 0:
                                            String str62 = DiagramMatchGameFragment.t;
                                            diagramMatchGameFragment2.W().G(c4347c22);
                                            break;
                                        case 1:
                                            String str7 = DiagramMatchGameFragment.t;
                                            diagramMatchGameFragment2.W().H(c4347c22);
                                            break;
                                        case 2:
                                            String str8 = DiagramMatchGameFragment.t;
                                            diagramMatchGameFragment2.W().H(c4347c22);
                                            break;
                                        default:
                                            String str9 = DiagramMatchGameFragment.t;
                                            diagramMatchGameFragment2.W().G(c4347c22);
                                            break;
                                    }
                                }
                            });
                            final int i5 = 2;
                            io.reactivex.rxjava3.internal.observers.e eVarF3 = iVar.f(new io.reactivex.rxjava3.functions.a() { // from class: com.quizlet.quizletandroid.ui.studymodes.match.fragment.a
                                @Override // io.reactivex.rxjava3.functions.a
                                public final void run() {
                                    C4347c c4347c22 = c4347c2;
                                    DiagramMatchGameFragment diagramMatchGameFragment2 = diagramMatchGameFragment;
                                    switch (i5) {
                                        case 0:
                                            String str62 = DiagramMatchGameFragment.t;
                                            diagramMatchGameFragment2.W().G(c4347c22);
                                            break;
                                        case 1:
                                            String str7 = DiagramMatchGameFragment.t;
                                            diagramMatchGameFragment2.W().H(c4347c22);
                                            break;
                                        case 2:
                                            String str8 = DiagramMatchGameFragment.t;
                                            diagramMatchGameFragment2.W().H(c4347c22);
                                            break;
                                        default:
                                            String str9 = DiagramMatchGameFragment.t;
                                            diagramMatchGameFragment2.W().G(c4347c22);
                                            break;
                                    }
                                }
                            }, gVar);
                            Intrinsics.checkNotNullExpressionValue(eVarF3, "subscribe(...)");
                            diagramMatchGameFragment.I(eVarF3);
                        }
                        return Unit.a;
                }
            }
        }));
        final int i4 = 3;
        W().h.f(this, new com.quizlet.explanations.feedback.ui.fragments.c(23, new Function1(this) { // from class: com.quizlet.quizletandroid.ui.studymodes.match.fragment.b
            public final /* synthetic */ DiagramMatchGameFragment b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object obj) {
                final int i22 = 0;
                final int i32 = 1;
                final DiagramMatchGameFragment diagramMatchGameFragment = this.b;
                switch (i4) {
                    case 0:
                        String str = DiagramMatchGameFragment.t;
                        ((com.quizlet.features.match.viewmodel.f) diagramMatchGameFragment.p.getValue()).B();
                        return Unit.a;
                    case 1:
                        String str2 = DiagramMatchGameFragment.t;
                        com.quizlet.features.match.viewmodel.f fVar = (com.quizlet.features.match.viewmodel.f) diagramMatchGameFragment.p.getValue();
                        com.quizlet.features.match.studyengine.e eVar = (com.quizlet.features.match.studyengine.e) fVar.c;
                        eVar.b();
                        eVar.g = System.currentTimeMillis();
                        fVar.e.l(C4360p.a);
                        return Unit.a;
                    case 2:
                        com.quizlet.features.match.data.C c = (com.quizlet.features.match.data.C) obj;
                        String str3 = DiagramMatchGameFragment.t;
                        if (c instanceof com.quizlet.features.match.data.A) {
                            C4346b c4346b = (C4346b) ((com.quizlet.features.match.data.A) c).a;
                            diagramMatchGameFragment.T(c4346b.c);
                            boolean z = diagramMatchGameFragment.s;
                            ArrayList arrayList = c4346b.b;
                            if (z) {
                                diagramMatchGameFragment.U(arrayList);
                            } else {
                                io.reactivex.rxjava3.core.i termClicks = diagramMatchGameFragment.V().getTermClicks();
                                io.reactivex.rxjava3.core.o oVar = diagramMatchGameFragment.o;
                                if (oVar == null) {
                                    Intrinsics.m("mainThreadScheduler");
                                    throw null;
                                }
                                W wS = termClicks.s(oVar);
                                com.quizlet.quizletandroid.ui.setpage.terms.c cVar = new com.quizlet.quizletandroid.ui.setpage.terms.c(diagramMatchGameFragment.W(), 4);
                                timber.log.a aVar = timber.log.c.a;
                                io.reactivex.rxjava3.disposables.b bVarU = wS.u(cVar, new com.quizlet.billing.manager.d(aVar, 15), io.reactivex.rxjava3.internal.functions.d.c);
                                Intrinsics.checkNotNullExpressionValue(bVarU, "subscribe(...)");
                                diagramMatchGameFragment.G(bVarU);
                                DiagramView diagramViewV = diagramMatchGameFragment.V();
                                com.quizlet.diagrams.b[] diagramLoadingConfigurations = new com.quizlet.diagrams.b[0];
                                diagramViewV.getClass();
                                DiagramData data = c4346b.a;
                                Intrinsics.checkNotNullParameter(data, "data");
                                Intrinsics.checkNotNullParameter(diagramLoadingConfigurations, "diagramLoadingConfigurations");
                                io.reactivex.rxjava3.internal.operators.completable.c cVar2 = new io.reactivex.rxjava3.internal.operators.completable.c(new T(diagramViewV, data, diagramLoadingConfigurations, 24), 1);
                                Intrinsics.checkNotNullExpressionValue(cVar2, "create(...)");
                                io.reactivex.rxjava3.core.o oVar2 = diagramMatchGameFragment.o;
                                if (oVar2 == null) {
                                    Intrinsics.m("mainThreadScheduler");
                                    throw null;
                                }
                                io.reactivex.rxjava3.internal.observers.e eVarF = new io.reactivex.rxjava3.internal.operators.completable.h(cVar2, oVar2, 0).f(new C4430d(5, diagramMatchGameFragment, arrayList), new com.quizlet.billing.manager.d(aVar, 16));
                                Intrinsics.checkNotNullExpressionValue(eVarF, "subscribe(...)");
                                diagramMatchGameFragment.G(eVarF);
                            }
                        } else {
                            if (!Intrinsics.b(c, com.quizlet.features.match.data.B.a)) {
                                throw new NoWhenBranchMatchedException();
                            }
                            kotlin.collections.K k = kotlin.collections.K.a;
                            diagramMatchGameFragment.T(k);
                            if (diagramMatchGameFragment.s) {
                                diagramMatchGameFragment.U(k);
                            }
                            com.quizlet.features.match.viewmodel.f fVar2 = (com.quizlet.features.match.viewmodel.f) diagramMatchGameFragment.p.getValue();
                            com.quizlet.features.match.studyengine.e eVar2 = (com.quizlet.features.match.studyengine.e) fVar2.c;
                            fVar2.d.o(new C4364u(eVar2.g, eVar2.h));
                        }
                        return Unit.a;
                    default:
                        AbstractC4352h abstractC4352h = (AbstractC4352h) obj;
                        String str4 = DiagramMatchGameFragment.t;
                        boolean z2 = abstractC4352h instanceof C4350f;
                        com.quizlet.infra.legacysyncengine.net.request.g gVar = io.reactivex.rxjava3.internal.functions.d.e;
                        io.reactivex.rxjava3.internal.functions.b bVar = io.reactivex.rxjava3.internal.functions.d.c;
                        com.quizlet.infra.legacysyncengine.net.request.g gVar2 = io.reactivex.rxjava3.internal.functions.d.d;
                        if (z2) {
                            final C4347c c4347c = (C4347c) ((C4350f) abstractC4352h).a;
                            com.quizlet.quizletandroid.ui.diagramming.j presenter = diagramMatchGameFragment.V().getPresenter();
                            presenter.getClass();
                            String str5 = String.format("onCorrectTerm('%d');", Arrays.copyOf(new Object[]{Long.valueOf(c4347c.b)}, 1));
                            Intrinsics.checkNotNullExpressionValue(str5, "format(...)");
                            presenter.a(str5);
                            List list = diagramMatchGameFragment.r;
                            if (list == null) {
                                Intrinsics.m("cards");
                                throw null;
                            }
                            final int i42 = 3;
                            io.reactivex.rxjava3.internal.observers.e eVarF2 = new io.reactivex.rxjava3.internal.operators.completable.i(((MatchCardView) list.get(c4347c.c)).d(), gVar2, gVar2, bVar, new io.reactivex.rxjava3.functions.a() { // from class: com.quizlet.quizletandroid.ui.studymodes.match.fragment.a
                                @Override // io.reactivex.rxjava3.functions.a
                                public final void run() {
                                    C4347c c4347c22 = c4347c;
                                    DiagramMatchGameFragment diagramMatchGameFragment2 = diagramMatchGameFragment;
                                    switch (i42) {
                                        case 0:
                                            String str62 = DiagramMatchGameFragment.t;
                                            diagramMatchGameFragment2.W().G(c4347c22);
                                            break;
                                        case 1:
                                            String str7 = DiagramMatchGameFragment.t;
                                            diagramMatchGameFragment2.W().H(c4347c22);
                                            break;
                                        case 2:
                                            String str8 = DiagramMatchGameFragment.t;
                                            diagramMatchGameFragment2.W().H(c4347c22);
                                            break;
                                        default:
                                            String str9 = DiagramMatchGameFragment.t;
                                            diagramMatchGameFragment2.W().G(c4347c22);
                                            break;
                                    }
                                }
                            }).f(new io.reactivex.rxjava3.functions.a() { // from class: com.quizlet.quizletandroid.ui.studymodes.match.fragment.a
                                @Override // io.reactivex.rxjava3.functions.a
                                public final void run() {
                                    C4347c c4347c22 = c4347c;
                                    DiagramMatchGameFragment diagramMatchGameFragment2 = diagramMatchGameFragment;
                                    switch (i22) {
                                        case 0:
                                            String str62 = DiagramMatchGameFragment.t;
                                            diagramMatchGameFragment2.W().G(c4347c22);
                                            break;
                                        case 1:
                                            String str7 = DiagramMatchGameFragment.t;
                                            diagramMatchGameFragment2.W().H(c4347c22);
                                            break;
                                        case 2:
                                            String str8 = DiagramMatchGameFragment.t;
                                            diagramMatchGameFragment2.W().H(c4347c22);
                                            break;
                                        default:
                                            String str9 = DiagramMatchGameFragment.t;
                                            diagramMatchGameFragment2.W().G(c4347c22);
                                            break;
                                    }
                                }
                            }, gVar);
                            Intrinsics.checkNotNullExpressionValue(eVarF2, "subscribe(...)");
                            diagramMatchGameFragment.I(eVarF2);
                        } else {
                            if (!(abstractC4352h instanceof C4351g)) {
                                throw new NoWhenBranchMatchedException();
                            }
                            final C4347c c4347c2 = (C4347c) ((C4351g) abstractC4352h).a;
                            ((com.quizlet.features.match.viewmodel.f) diagramMatchGameFragment.p.getValue()).C();
                            com.quizlet.quizletandroid.ui.diagramming.j presenter2 = diagramMatchGameFragment.V().getPresenter();
                            presenter2.getClass();
                            String str6 = String.format("onIncorrectTerm('%d');", Arrays.copyOf(new Object[]{Long.valueOf(c4347c2.b)}, 1));
                            Intrinsics.checkNotNullExpressionValue(str6, "format(...)");
                            presenter2.a(str6);
                            List list2 = diagramMatchGameFragment.r;
                            if (list2 == null) {
                                Intrinsics.m("cards");
                                throw null;
                            }
                            io.reactivex.rxjava3.internal.operators.completable.i iVar = new io.reactivex.rxjava3.internal.operators.completable.i(((MatchCardView) list2.get(c4347c2.c)).e(), gVar2, gVar2, bVar, new io.reactivex.rxjava3.functions.a() { // from class: com.quizlet.quizletandroid.ui.studymodes.match.fragment.a
                                @Override // io.reactivex.rxjava3.functions.a
                                public final void run() {
                                    C4347c c4347c22 = c4347c2;
                                    DiagramMatchGameFragment diagramMatchGameFragment2 = diagramMatchGameFragment;
                                    switch (i32) {
                                        case 0:
                                            String str62 = DiagramMatchGameFragment.t;
                                            diagramMatchGameFragment2.W().G(c4347c22);
                                            break;
                                        case 1:
                                            String str7 = DiagramMatchGameFragment.t;
                                            diagramMatchGameFragment2.W().H(c4347c22);
                                            break;
                                        case 2:
                                            String str8 = DiagramMatchGameFragment.t;
                                            diagramMatchGameFragment2.W().H(c4347c22);
                                            break;
                                        default:
                                            String str9 = DiagramMatchGameFragment.t;
                                            diagramMatchGameFragment2.W().G(c4347c22);
                                            break;
                                    }
                                }
                            });
                            final int i5 = 2;
                            io.reactivex.rxjava3.internal.observers.e eVarF3 = iVar.f(new io.reactivex.rxjava3.functions.a() { // from class: com.quizlet.quizletandroid.ui.studymodes.match.fragment.a
                                @Override // io.reactivex.rxjava3.functions.a
                                public final void run() {
                                    C4347c c4347c22 = c4347c2;
                                    DiagramMatchGameFragment diagramMatchGameFragment2 = diagramMatchGameFragment;
                                    switch (i5) {
                                        case 0:
                                            String str62 = DiagramMatchGameFragment.t;
                                            diagramMatchGameFragment2.W().G(c4347c22);
                                            break;
                                        case 1:
                                            String str7 = DiagramMatchGameFragment.t;
                                            diagramMatchGameFragment2.W().H(c4347c22);
                                            break;
                                        case 2:
                                            String str8 = DiagramMatchGameFragment.t;
                                            diagramMatchGameFragment2.W().H(c4347c22);
                                            break;
                                        default:
                                            String str9 = DiagramMatchGameFragment.t;
                                            diagramMatchGameFragment2.W().G(c4347c22);
                                            break;
                                    }
                                }
                            }, gVar);
                            Intrinsics.checkNotNullExpressionValue(eVarF3, "subscribe(...)");
                            diagramMatchGameFragment.I(eVarF3);
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
        C4621z c4621z = (C4621z) J();
        List listJ = B.j(c4621z.c, c4621z.d, c4621z.e, c4621z.f, c4621z.g, c4621z.h);
        this.r = listJ;
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
            matchCardView.setOnTouchListener(new c(this, i, 0));
            i = i2;
        }
    }
}

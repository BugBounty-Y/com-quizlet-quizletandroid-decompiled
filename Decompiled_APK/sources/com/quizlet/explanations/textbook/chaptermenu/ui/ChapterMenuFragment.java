package com.quizlet.explanations.textbook.chaptermenu.ui;

import android.content.Context;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.onetrust.otpublishers.headless.UI.fragment.C4062f;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.data.repository.folderwithcreatorinclass.e;
import com.quizlet.explanations.databinding.d;
import com.quizlet.explanations.textbook.chaptermenu.data.c;
import com.quizlet.explanations.textbook.chaptermenu.data.f;
import com.quizlet.explanations.textbook.chaptermenu.data.g;
import com.quizlet.explanations.textbook.data.TextbookSetUpState;
import com.quizlet.quizletandroid.R;
import java.util.List;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.collections.C4927s;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;
import kotlin.k;
import kotlin.l;
import kotlin.m;

@Metadata
/* loaded from: classes2.dex */
public final class ChapterMenuFragment extends Hilt_ChapterMenuFragment<d> {
    public static final String n;
    public com.google.firebase.perf.logging.b j;
    public com.quizlet.explanations.myexplanations.ui.recyclerview.b k;
    public final e l;
    public final e m;

    static {
        Intrinsics.checkNotNullExpressionValue("ChapterMenuFragment", "getSimpleName(...)");
        n = "ChapterMenuFragment";
    }

    public ChapterMenuFragment() {
        k kVarA = l.a(m.c, new assistantMode.experiments.a(new assistantMode.experiments.a(this, 17), 18));
        this.l = new e(K.a(com.quizlet.explanations.textbook.chaptermenu.viewmodel.b.class), new C4062f(kVarA, 18), new androidx.credentials.playservices.controllers.BeginSignIn.d(21, this, kVarA), new C4062f(kVarA, 19));
        this.m = new e(K.a(com.quizlet.explanations.textbook.viewmodel.c.class), new b(this, 0), new b(this, 2), new b(this, 1));
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final String N() {
        return n;
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final androidx.viewbinding.a O(LayoutInflater inflater, ViewGroup viewGroup) {
        Intrinsics.checkNotNullParameter(inflater, "inflater");
        View viewInflate = inflater.inflate(R.layout.fragment_chapter_menu, viewGroup, false);
        RecyclerView recyclerView = (RecyclerView) AbstractC3375o2.c(R.id.chapterMenuRecyclerView, viewInflate);
        if (recyclerView == null) {
            throw new NullPointerException("Missing required view with ID: ".concat(viewInflate.getResources().getResourceName(R.id.chapterMenuRecyclerView)));
        }
        d dVar = new d((ConstraintLayout) viewInflate, recyclerView);
        Intrinsics.checkNotNullExpressionValue(dVar, "inflate(...)");
        return dVar;
    }

    public final RecyclerView T() {
        RecyclerView chapterMenuRecyclerView = ((d) J()).b;
        Intrinsics.checkNotNullExpressionValue(chapterMenuRecyclerView, "chapterMenuRecyclerView");
        return chapterMenuRecyclerView;
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onDestroyView() {
        T().setAdapter(null);
        super.onDestroyView();
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onStart() {
        com.quizlet.explanations.textbook.chaptermenu.data.e chapterMenuState;
        super.onStart();
        com.quizlet.explanations.textbook.viewmodel.c cVar = (com.quizlet.explanations.textbook.viewmodel.c) this.m.getValue();
        C4927s c4927s = cVar.n;
        if (c4927s.isEmpty()) {
            TextbookSetUpState textbookSetUpState = cVar.l;
            if (textbookSetUpState != null) {
                cVar.E(textbookSetUpState);
            }
            chapterMenuState = null;
        } else {
            chapterMenuState = (com.quizlet.explanations.textbook.chaptermenu.data.e) c4927s.last();
        }
        if (chapterMenuState != null) {
            final com.quizlet.explanations.textbook.chaptermenu.viewmodel.b bVar = (com.quizlet.explanations.textbook.chaptermenu.viewmodel.b) this.l.getValue();
            requireArguments().getBoolean("is_premium_text_book");
            bVar.getClass();
            Intrinsics.checkNotNullParameter(chapterMenuState, "chapterMenuState");
            final int i = 0;
            Function1 onChapter = new Function1() { // from class: com.quizlet.explanations.textbook.chaptermenu.viewmodel.a
                @Override // kotlin.jvm.functions.Function1
                public final Object invoke(Object obj) {
                    switch (i) {
                        case 0:
                            com.quizlet.explanations.textbook.chaptermenu.data.b it2 = (com.quizlet.explanations.textbook.chaptermenu.data.b) obj;
                            Intrinsics.checkNotNullParameter(it2, "it");
                            bVar.B(it2.a);
                            break;
                        case 1:
                            com.quizlet.explanations.textbook.chaptermenu.data.d it3 = (com.quizlet.explanations.textbook.chaptermenu.data.d) obj;
                            Intrinsics.checkNotNullParameter(it3, "it");
                            bVar.B(it3.a);
                            break;
                        default:
                            c it4 = (c) obj;
                            Intrinsics.checkNotNullParameter(it4, "it");
                            bVar.B(it4.a);
                            break;
                    }
                    return Unit.a;
                }
            };
            final int i2 = 1;
            Function1 onSection = new Function1() { // from class: com.quizlet.explanations.textbook.chaptermenu.viewmodel.a
                @Override // kotlin.jvm.functions.Function1
                public final Object invoke(Object obj) {
                    switch (i2) {
                        case 0:
                            com.quizlet.explanations.textbook.chaptermenu.data.b it2 = (com.quizlet.explanations.textbook.chaptermenu.data.b) obj;
                            Intrinsics.checkNotNullParameter(it2, "it");
                            bVar.B(it2.a);
                            break;
                        case 1:
                            com.quizlet.explanations.textbook.chaptermenu.data.d it3 = (com.quizlet.explanations.textbook.chaptermenu.data.d) obj;
                            Intrinsics.checkNotNullParameter(it3, "it");
                            bVar.B(it3.a);
                            break;
                        default:
                            c it4 = (c) obj;
                            Intrinsics.checkNotNullParameter(it4, "it");
                            bVar.B(it4.a);
                            break;
                    }
                    return Unit.a;
                }
            };
            final int i3 = 2;
            Function1 onExerciseGroup = new Function1() { // from class: com.quizlet.explanations.textbook.chaptermenu.viewmodel.a
                @Override // kotlin.jvm.functions.Function1
                public final Object invoke(Object obj) {
                    switch (i3) {
                        case 0:
                            com.quizlet.explanations.textbook.chaptermenu.data.b it2 = (com.quizlet.explanations.textbook.chaptermenu.data.b) obj;
                            Intrinsics.checkNotNullParameter(it2, "it");
                            bVar.B(it2.a);
                            break;
                        case 1:
                            com.quizlet.explanations.textbook.chaptermenu.data.d it3 = (com.quizlet.explanations.textbook.chaptermenu.data.d) obj;
                            Intrinsics.checkNotNullParameter(it3, "it");
                            bVar.B(it3.a);
                            break;
                        default:
                            c it4 = (c) obj;
                            Intrinsics.checkNotNullParameter(it4, "it");
                            bVar.B(it4.a);
                            break;
                    }
                    return Unit.a;
                }
            };
            Intrinsics.checkNotNullParameter(onChapter, "onChapter");
            Intrinsics.checkNotNullParameter(onSection, "onSection");
            Intrinsics.checkNotNullParameter(onExerciseGroup, "onExerciseGroup");
            if (chapterMenuState instanceof com.quizlet.explanations.textbook.chaptermenu.data.b) {
                onChapter.invoke(chapterMenuState);
            } else if (chapterMenuState instanceof com.quizlet.explanations.textbook.chaptermenu.data.d) {
                onSection.invoke(chapterMenuState);
            } else {
                if (!(chapterMenuState instanceof com.quizlet.explanations.textbook.chaptermenu.data.c)) {
                    throw new NoWhenBranchMatchedException();
                }
                onExerciseGroup.invoke(chapterMenuState);
            }
        }
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onViewCreated(View view, Bundle bundle) {
        Intrinsics.checkNotNullParameter(view, "view");
        super.onViewCreated(view, bundle);
        if (this.j == null) {
            Intrinsics.m("adapterFactory");
            throw null;
        }
        this.k = new com.quizlet.explanations.myexplanations.ui.recyclerview.b(AbstractC4178x.h("diffUtilCallback"), 4);
        RecyclerView recyclerViewT = T();
        com.quizlet.explanations.myexplanations.ui.recyclerview.b bVar = this.k;
        if (bVar == null) {
            Intrinsics.m("adapter");
            throw null;
        }
        recyclerViewT.setAdapter(bVar);
        RecyclerView recyclerViewT2 = T();
        requireContext();
        recyclerViewT2.setLayoutManager(new LinearLayoutManager(1));
        com.quizlet.baserecyclerview.decoration.c cVar = new com.quizlet.baserecyclerview.decoration.c(T().getContext(), 1, getResources().getDimensionPixelSize(R.dimen.quizlet_edge_margin), com.quizlet.baserecyclerview.decoration.b.Z0);
        Context contextRequireContext = requireContext();
        Intrinsics.checkNotNullExpressionValue(contextRequireContext, "requireContext(...)");
        cVar.a.setColor(com.quizlet.themes.extensions.a.a(contextRequireContext, R.attr.AssemblyDisabledTintColor));
        T().i(cVar);
        e eVar = this.l;
        final int i = 1;
        ((com.quizlet.explanations.textbook.chaptermenu.viewmodel.b) eVar.getValue()).d.f(getViewLifecycleOwner(), new com.quizlet.explanations.feedback.ui.fragments.c(2, new Function1(this) { // from class: com.quizlet.explanations.textbook.chaptermenu.ui.a
            public final /* synthetic */ ChapterMenuFragment b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object obj) {
                ChapterMenuFragment chapterMenuFragment = this.b;
                switch (i) {
                    case 0:
                        List list = (List) obj;
                        com.quizlet.explanations.myexplanations.ui.recyclerview.b bVar2 = chapterMenuFragment.k;
                        if (bVar2 == null) {
                            Intrinsics.m("adapter");
                            throw null;
                        }
                        bVar2.f(list);
                        ((com.quizlet.explanations.textbook.viewmodel.c) chapterMenuFragment.m.getValue()).D();
                        return Unit.a;
                    default:
                        com.quizlet.explanations.textbook.chaptermenu.data.a aVar = (com.quizlet.explanations.textbook.chaptermenu.data.a) obj;
                        String str = ChapterMenuFragment.n;
                        boolean z = aVar instanceof f;
                        e eVar2 = chapterMenuFragment.m;
                        if (z) {
                            ((com.quizlet.explanations.textbook.viewmodel.c) eVar2.getValue()).B(((f) aVar).a);
                        } else {
                            if (!(aVar instanceof g)) {
                                throw new NoWhenBranchMatchedException();
                            }
                            ((com.quizlet.explanations.textbook.viewmodel.c) eVar2.getValue()).C(((g) aVar).a, false);
                        }
                        return Unit.a;
                }
            }
        }));
        final int i2 = 0;
        ((com.quizlet.explanations.textbook.chaptermenu.viewmodel.b) eVar.getValue()).e.f(getViewLifecycleOwner(), new com.quizlet.explanations.feedback.ui.fragments.c(2, new Function1(this) { // from class: com.quizlet.explanations.textbook.chaptermenu.ui.a
            public final /* synthetic */ ChapterMenuFragment b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object obj) {
                ChapterMenuFragment chapterMenuFragment = this.b;
                switch (i2) {
                    case 0:
                        List list = (List) obj;
                        com.quizlet.explanations.myexplanations.ui.recyclerview.b bVar2 = chapterMenuFragment.k;
                        if (bVar2 == null) {
                            Intrinsics.m("adapter");
                            throw null;
                        }
                        bVar2.f(list);
                        ((com.quizlet.explanations.textbook.viewmodel.c) chapterMenuFragment.m.getValue()).D();
                        return Unit.a;
                    default:
                        com.quizlet.explanations.textbook.chaptermenu.data.a aVar = (com.quizlet.explanations.textbook.chaptermenu.data.a) obj;
                        String str = ChapterMenuFragment.n;
                        boolean z = aVar instanceof f;
                        e eVar2 = chapterMenuFragment.m;
                        if (z) {
                            ((com.quizlet.explanations.textbook.viewmodel.c) eVar2.getValue()).B(((f) aVar).a);
                        } else {
                            if (!(aVar instanceof g)) {
                                throw new NoWhenBranchMatchedException();
                            }
                            ((com.quizlet.explanations.textbook.viewmodel.c) eVar2.getValue()).C(((g) aVar).a, false);
                        }
                        return Unit.a;
                }
            }
        }));
    }
}

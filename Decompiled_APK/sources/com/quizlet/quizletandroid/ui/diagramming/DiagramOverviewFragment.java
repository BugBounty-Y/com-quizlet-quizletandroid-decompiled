package com.quizlet.quizletandroid.ui.diagramming;

import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.animation.AnimationUtils;
import android.widget.RelativeLayout;
import androidx.recyclerview.widget.C1397z;
import com.google.android.gms.internal.mlkit_vision_barcode.A7;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.quizlet.db.data.models.persisted.DBSelectedTerm;
import com.quizlet.db.data.models.persisted.DBTerm;
import com.quizlet.diagrams.layoutmanager.DiagramCardLayoutManager;
import com.quizlet.diagrams.layoutmanager.SnapRecyclerView;
import com.quizlet.generated.enums.O1;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.databinding.r;
import com.quizlet.studiablemodels.diagrams.DiagramData;
import io.reactivex.rxjava3.core.o;
import io.reactivex.rxjava3.core.p;
import io.reactivex.rxjava3.internal.operators.observable.C4885d;
import io.reactivex.rxjava3.internal.operators.observable.C4887f;
import java.io.IOException;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import kotlin.Metadata;
import kotlin.Pair;
import kotlin.collections.K;
import kotlin.jvm.internal.Intrinsics;
import kotlin.l;
import kotlin.u;

@Metadata
/* loaded from: classes3.dex */
public final class DiagramOverviewFragment extends Hilt_DiagramOverviewFragment<r> {
    public com.google.mlkit.vision.documentscanner.internal.c j;
    public o k;
    public h l;
    public com.quizlet.diagrams.e m;
    public long o;
    public final g q;
    public final g r;
    public final g s;
    public final g t;
    public final g u;
    public final g v;
    public final u n = l.b(new com.quizlet.login.magiclink.ui.e(this, 12));
    public final io.reactivex.rxjava3.disposables.a p = new io.reactivex.rxjava3.disposables.a();
    public final com.quizlet.billing.subscriptions.c w = new com.quizlet.billing.subscriptions.c(4);
    public final C1397z x = new C1397z(this, 1);

    /* JADX WARN: Type inference failed for: r0v3, types: [com.quizlet.quizletandroid.ui.diagramming.g] */
    /* JADX WARN: Type inference failed for: r0v4, types: [com.quizlet.quizletandroid.ui.diagramming.g] */
    /* JADX WARN: Type inference failed for: r0v5, types: [com.quizlet.quizletandroid.ui.diagramming.g] */
    /* JADX WARN: Type inference failed for: r0v6, types: [com.quizlet.quizletandroid.ui.diagramming.g] */
    /* JADX WARN: Type inference failed for: r0v7, types: [com.quizlet.quizletandroid.ui.diagramming.g] */
    /* JADX WARN: Type inference failed for: r0v8, types: [com.quizlet.quizletandroid.ui.diagramming.g] */
    public DiagramOverviewFragment() {
        final int i = 0;
        this.q = new io.reactivex.rxjava3.functions.d(this) { // from class: com.quizlet.quizletandroid.ui.diagramming.g
            public final /* synthetic */ DiagramOverviewFragment b;

            {
                this.b = this;
            }

            @Override // io.reactivex.rxjava3.functions.d
            public final void accept(Object obj) throws IOException {
                switch (i) {
                    case 0:
                        DiagramData diagramData = (DiagramData) obj;
                        Intrinsics.checkNotNullParameter(diagramData, "diagramData");
                        DiagramOverviewFragment diagramOverviewFragment = this.b;
                        DiagramView setpageDiagramDiagramView = ((r) diagramOverviewFragment.J()).b;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDiagramView, "setpageDiagramDiagramView");
                        setpageDiagramDiagramView.d(diagramData, com.quizlet.diagrams.b.b);
                        com.quizlet.diagrams.e eVar = diagramOverviewFragment.m;
                        if (eVar != null) {
                            eVar.notifyDataSetChanged();
                            return;
                        } else {
                            Intrinsics.m("adapter");
                            throw null;
                        }
                    case 1:
                        List terms = (List) obj;
                        Intrinsics.checkNotNullParameter(terms, "terms");
                        DiagramOverviewFragment diagramOverviewFragment2 = this.b;
                        com.quizlet.diagrams.e eVar2 = diagramOverviewFragment2.m;
                        if (eVar2 == null) {
                            Intrinsics.m("adapter");
                            throw null;
                        }
                        Intrinsics.checkNotNullParameter(terms, "<set-?>");
                        eVar2.a = terms;
                        com.quizlet.diagrams.e eVar3 = diagramOverviewFragment2.m;
                        if (eVar3 == null) {
                            Intrinsics.m("adapter");
                            throw null;
                        }
                        eVar3.notifyDataSetChanged();
                        if (diagramOverviewFragment2.o == 0 || diagramOverviewFragment2.U().getVisibility() != 8) {
                            return;
                        }
                        com.quizlet.diagrams.e eVar4 = diagramOverviewFragment2.m;
                        if (eVar4 == null) {
                            Intrinsics.m("adapter");
                            throw null;
                        }
                        Iterator it2 = eVar4.a.iterator();
                        int i2 = 0;
                        while (true) {
                            if (it2.hasNext()) {
                                if (diagramOverviewFragment2.o != ((DBTerm) ((Pair) it2.next()).a).getId()) {
                                    i2++;
                                }
                            } else {
                                i2 = -1;
                            }
                        }
                        diagramOverviewFragment2.U().k0(i2);
                        diagramOverviewFragment2.U().setVisibility(0);
                        return;
                    case 2:
                        com.quizlet.diagrams.f fVar = (com.quizlet.diagrams.f) obj;
                        Intrinsics.checkNotNullParameter(fVar, "<destruct>");
                        long j = fVar.a;
                        DiagramOverviewFragment diagramOverviewFragment3 = this.b;
                        com.quizlet.diagrams.e eVar5 = diagramOverviewFragment3.m;
                        if (eVar5 == null) {
                            Intrinsics.m("adapter");
                            throw null;
                        }
                        Iterator it3 = eVar5.a.iterator();
                        int i3 = 0;
                        while (true) {
                            if (!it3.hasNext()) {
                                i3 = -1;
                            } else if (j != ((DBTerm) ((Pair) it3.next()).a).getId()) {
                                i3++;
                            }
                        }
                        int iQ1 = ((DiagramCardLayoutManager) diagramOverviewFragment3.n.getValue()).q1();
                        boolean z = diagramOverviewFragment3.U().getVisibility() == 8;
                        if (z) {
                            diagramOverviewFragment3.U().startAnimation(AnimationUtils.loadAnimation(diagramOverviewFragment3.getContext(), R.anim.slide_up));
                            diagramOverviewFragment3.U().setVisibility(0);
                        }
                        int i4 = iQ1 - i3;
                        diagramOverviewFragment3.V(j);
                        com.quizlet.diagrams.e eVar6 = diagramOverviewFragment3.m;
                        if (eVar6 == null) {
                            Intrinsics.m("adapter");
                            throw null;
                        }
                        if (eVar6.c != j) {
                            eVar6.c = j;
                            eVar6.notifyDataSetChanged();
                        }
                        if (Math.abs(i4) > 2 || z) {
                            diagramOverviewFragment3.U().k0(i3);
                            return;
                        } else {
                            diagramOverviewFragment3.U().n0(i3);
                            return;
                        }
                    case 3:
                        com.quizlet.diagrams.a aVar = (com.quizlet.diagrams.a) obj;
                        Intrinsics.checkNotNullParameter(aVar, "<destruct>");
                        Pair termData = aVar.a;
                        DiagramOverviewFragment diagramOverviewFragment4 = this.b;
                        if (!aVar.c) {
                            diagramOverviewFragment4.U().n0(aVar.b.getAdapterPosition());
                            return;
                        }
                        h hVar = diagramOverviewFragment4.l;
                        if (hVar != null) {
                            DiagramOverviewActivity diagramOverviewActivity = (DiagramOverviewActivity) hVar;
                            Intrinsics.checkNotNullParameter(termData, "termData");
                            Intrinsics.checkNotNullParameter(termData, "termData");
                            diagramOverviewActivity.b0(termData);
                            diagramOverviewActivity.c0().J(3);
                            return;
                        }
                        return;
                    case 4:
                        com.quizlet.diagrams.a it4 = (com.quizlet.diagrams.a) obj;
                        Intrinsics.checkNotNullParameter(it4, "it");
                        h hVar2 = this.b.l;
                        if (hVar2 != null) {
                            Pair termData2 = it4.a;
                            DiagramOverviewActivity diagramOverviewActivity2 = (DiagramOverviewActivity) hVar2;
                            Intrinsics.checkNotNullParameter(termData2, "termData");
                            ((com.quizlet.quizletandroid.ui.common.adapter.presenter.e) diagramOverviewActivity2.f1.getValue()).c(diagramOverviewActivity2, diagramOverviewActivity2.m1, (DBTerm) termData2.a, O1.WORD, true);
                            return;
                        }
                        return;
                    default:
                        com.quizlet.diagrams.a it5 = (com.quizlet.diagrams.a) obj;
                        Intrinsics.checkNotNullParameter(it5, "it");
                        h hVar3 = this.b.l;
                        if (hVar3 != null) {
                            Pair termData3 = it5.a;
                            Intrinsics.checkNotNullParameter(termData3, "termData");
                            ((com.quizlet.quizletandroid.ui.common.adapter.presenter.e) ((DiagramOverviewActivity) hVar3).f1.getValue()).b((DBTerm) termData3.a, (DBSelectedTerm) termData3.b, 0);
                            return;
                        }
                        return;
                }
            }
        };
        final int i2 = 1;
        this.r = new io.reactivex.rxjava3.functions.d(this) { // from class: com.quizlet.quizletandroid.ui.diagramming.g
            public final /* synthetic */ DiagramOverviewFragment b;

            {
                this.b = this;
            }

            @Override // io.reactivex.rxjava3.functions.d
            public final void accept(Object obj) throws IOException {
                switch (i2) {
                    case 0:
                        DiagramData diagramData = (DiagramData) obj;
                        Intrinsics.checkNotNullParameter(diagramData, "diagramData");
                        DiagramOverviewFragment diagramOverviewFragment = this.b;
                        DiagramView setpageDiagramDiagramView = ((r) diagramOverviewFragment.J()).b;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDiagramView, "setpageDiagramDiagramView");
                        setpageDiagramDiagramView.d(diagramData, com.quizlet.diagrams.b.b);
                        com.quizlet.diagrams.e eVar = diagramOverviewFragment.m;
                        if (eVar != null) {
                            eVar.notifyDataSetChanged();
                            return;
                        } else {
                            Intrinsics.m("adapter");
                            throw null;
                        }
                    case 1:
                        List terms = (List) obj;
                        Intrinsics.checkNotNullParameter(terms, "terms");
                        DiagramOverviewFragment diagramOverviewFragment2 = this.b;
                        com.quizlet.diagrams.e eVar2 = diagramOverviewFragment2.m;
                        if (eVar2 == null) {
                            Intrinsics.m("adapter");
                            throw null;
                        }
                        Intrinsics.checkNotNullParameter(terms, "<set-?>");
                        eVar2.a = terms;
                        com.quizlet.diagrams.e eVar3 = diagramOverviewFragment2.m;
                        if (eVar3 == null) {
                            Intrinsics.m("adapter");
                            throw null;
                        }
                        eVar3.notifyDataSetChanged();
                        if (diagramOverviewFragment2.o == 0 || diagramOverviewFragment2.U().getVisibility() != 8) {
                            return;
                        }
                        com.quizlet.diagrams.e eVar4 = diagramOverviewFragment2.m;
                        if (eVar4 == null) {
                            Intrinsics.m("adapter");
                            throw null;
                        }
                        Iterator it2 = eVar4.a.iterator();
                        int i22 = 0;
                        while (true) {
                            if (it2.hasNext()) {
                                if (diagramOverviewFragment2.o != ((DBTerm) ((Pair) it2.next()).a).getId()) {
                                    i22++;
                                }
                            } else {
                                i22 = -1;
                            }
                        }
                        diagramOverviewFragment2.U().k0(i22);
                        diagramOverviewFragment2.U().setVisibility(0);
                        return;
                    case 2:
                        com.quizlet.diagrams.f fVar = (com.quizlet.diagrams.f) obj;
                        Intrinsics.checkNotNullParameter(fVar, "<destruct>");
                        long j = fVar.a;
                        DiagramOverviewFragment diagramOverviewFragment3 = this.b;
                        com.quizlet.diagrams.e eVar5 = diagramOverviewFragment3.m;
                        if (eVar5 == null) {
                            Intrinsics.m("adapter");
                            throw null;
                        }
                        Iterator it3 = eVar5.a.iterator();
                        int i3 = 0;
                        while (true) {
                            if (!it3.hasNext()) {
                                i3 = -1;
                            } else if (j != ((DBTerm) ((Pair) it3.next()).a).getId()) {
                                i3++;
                            }
                        }
                        int iQ1 = ((DiagramCardLayoutManager) diagramOverviewFragment3.n.getValue()).q1();
                        boolean z = diagramOverviewFragment3.U().getVisibility() == 8;
                        if (z) {
                            diagramOverviewFragment3.U().startAnimation(AnimationUtils.loadAnimation(diagramOverviewFragment3.getContext(), R.anim.slide_up));
                            diagramOverviewFragment3.U().setVisibility(0);
                        }
                        int i4 = iQ1 - i3;
                        diagramOverviewFragment3.V(j);
                        com.quizlet.diagrams.e eVar6 = diagramOverviewFragment3.m;
                        if (eVar6 == null) {
                            Intrinsics.m("adapter");
                            throw null;
                        }
                        if (eVar6.c != j) {
                            eVar6.c = j;
                            eVar6.notifyDataSetChanged();
                        }
                        if (Math.abs(i4) > 2 || z) {
                            diagramOverviewFragment3.U().k0(i3);
                            return;
                        } else {
                            diagramOverviewFragment3.U().n0(i3);
                            return;
                        }
                    case 3:
                        com.quizlet.diagrams.a aVar = (com.quizlet.diagrams.a) obj;
                        Intrinsics.checkNotNullParameter(aVar, "<destruct>");
                        Pair termData = aVar.a;
                        DiagramOverviewFragment diagramOverviewFragment4 = this.b;
                        if (!aVar.c) {
                            diagramOverviewFragment4.U().n0(aVar.b.getAdapterPosition());
                            return;
                        }
                        h hVar = diagramOverviewFragment4.l;
                        if (hVar != null) {
                            DiagramOverviewActivity diagramOverviewActivity = (DiagramOverviewActivity) hVar;
                            Intrinsics.checkNotNullParameter(termData, "termData");
                            Intrinsics.checkNotNullParameter(termData, "termData");
                            diagramOverviewActivity.b0(termData);
                            diagramOverviewActivity.c0().J(3);
                            return;
                        }
                        return;
                    case 4:
                        com.quizlet.diagrams.a it4 = (com.quizlet.diagrams.a) obj;
                        Intrinsics.checkNotNullParameter(it4, "it");
                        h hVar2 = this.b.l;
                        if (hVar2 != null) {
                            Pair termData2 = it4.a;
                            DiagramOverviewActivity diagramOverviewActivity2 = (DiagramOverviewActivity) hVar2;
                            Intrinsics.checkNotNullParameter(termData2, "termData");
                            ((com.quizlet.quizletandroid.ui.common.adapter.presenter.e) diagramOverviewActivity2.f1.getValue()).c(diagramOverviewActivity2, diagramOverviewActivity2.m1, (DBTerm) termData2.a, O1.WORD, true);
                            return;
                        }
                        return;
                    default:
                        com.quizlet.diagrams.a it5 = (com.quizlet.diagrams.a) obj;
                        Intrinsics.checkNotNullParameter(it5, "it");
                        h hVar3 = this.b.l;
                        if (hVar3 != null) {
                            Pair termData3 = it5.a;
                            Intrinsics.checkNotNullParameter(termData3, "termData");
                            ((com.quizlet.quizletandroid.ui.common.adapter.presenter.e) ((DiagramOverviewActivity) hVar3).f1.getValue()).b((DBTerm) termData3.a, (DBSelectedTerm) termData3.b, 0);
                            return;
                        }
                        return;
                }
            }
        };
        final int i3 = 2;
        this.s = new io.reactivex.rxjava3.functions.d(this) { // from class: com.quizlet.quizletandroid.ui.diagramming.g
            public final /* synthetic */ DiagramOverviewFragment b;

            {
                this.b = this;
            }

            @Override // io.reactivex.rxjava3.functions.d
            public final void accept(Object obj) throws IOException {
                switch (i3) {
                    case 0:
                        DiagramData diagramData = (DiagramData) obj;
                        Intrinsics.checkNotNullParameter(diagramData, "diagramData");
                        DiagramOverviewFragment diagramOverviewFragment = this.b;
                        DiagramView setpageDiagramDiagramView = ((r) diagramOverviewFragment.J()).b;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDiagramView, "setpageDiagramDiagramView");
                        setpageDiagramDiagramView.d(diagramData, com.quizlet.diagrams.b.b);
                        com.quizlet.diagrams.e eVar = diagramOverviewFragment.m;
                        if (eVar != null) {
                            eVar.notifyDataSetChanged();
                            return;
                        } else {
                            Intrinsics.m("adapter");
                            throw null;
                        }
                    case 1:
                        List terms = (List) obj;
                        Intrinsics.checkNotNullParameter(terms, "terms");
                        DiagramOverviewFragment diagramOverviewFragment2 = this.b;
                        com.quizlet.diagrams.e eVar2 = diagramOverviewFragment2.m;
                        if (eVar2 == null) {
                            Intrinsics.m("adapter");
                            throw null;
                        }
                        Intrinsics.checkNotNullParameter(terms, "<set-?>");
                        eVar2.a = terms;
                        com.quizlet.diagrams.e eVar3 = diagramOverviewFragment2.m;
                        if (eVar3 == null) {
                            Intrinsics.m("adapter");
                            throw null;
                        }
                        eVar3.notifyDataSetChanged();
                        if (diagramOverviewFragment2.o == 0 || diagramOverviewFragment2.U().getVisibility() != 8) {
                            return;
                        }
                        com.quizlet.diagrams.e eVar4 = diagramOverviewFragment2.m;
                        if (eVar4 == null) {
                            Intrinsics.m("adapter");
                            throw null;
                        }
                        Iterator it2 = eVar4.a.iterator();
                        int i22 = 0;
                        while (true) {
                            if (it2.hasNext()) {
                                if (diagramOverviewFragment2.o != ((DBTerm) ((Pair) it2.next()).a).getId()) {
                                    i22++;
                                }
                            } else {
                                i22 = -1;
                            }
                        }
                        diagramOverviewFragment2.U().k0(i22);
                        diagramOverviewFragment2.U().setVisibility(0);
                        return;
                    case 2:
                        com.quizlet.diagrams.f fVar = (com.quizlet.diagrams.f) obj;
                        Intrinsics.checkNotNullParameter(fVar, "<destruct>");
                        long j = fVar.a;
                        DiagramOverviewFragment diagramOverviewFragment3 = this.b;
                        com.quizlet.diagrams.e eVar5 = diagramOverviewFragment3.m;
                        if (eVar5 == null) {
                            Intrinsics.m("adapter");
                            throw null;
                        }
                        Iterator it3 = eVar5.a.iterator();
                        int i32 = 0;
                        while (true) {
                            if (!it3.hasNext()) {
                                i32 = -1;
                            } else if (j != ((DBTerm) ((Pair) it3.next()).a).getId()) {
                                i32++;
                            }
                        }
                        int iQ1 = ((DiagramCardLayoutManager) diagramOverviewFragment3.n.getValue()).q1();
                        boolean z = diagramOverviewFragment3.U().getVisibility() == 8;
                        if (z) {
                            diagramOverviewFragment3.U().startAnimation(AnimationUtils.loadAnimation(diagramOverviewFragment3.getContext(), R.anim.slide_up));
                            diagramOverviewFragment3.U().setVisibility(0);
                        }
                        int i4 = iQ1 - i32;
                        diagramOverviewFragment3.V(j);
                        com.quizlet.diagrams.e eVar6 = diagramOverviewFragment3.m;
                        if (eVar6 == null) {
                            Intrinsics.m("adapter");
                            throw null;
                        }
                        if (eVar6.c != j) {
                            eVar6.c = j;
                            eVar6.notifyDataSetChanged();
                        }
                        if (Math.abs(i4) > 2 || z) {
                            diagramOverviewFragment3.U().k0(i32);
                            return;
                        } else {
                            diagramOverviewFragment3.U().n0(i32);
                            return;
                        }
                    case 3:
                        com.quizlet.diagrams.a aVar = (com.quizlet.diagrams.a) obj;
                        Intrinsics.checkNotNullParameter(aVar, "<destruct>");
                        Pair termData = aVar.a;
                        DiagramOverviewFragment diagramOverviewFragment4 = this.b;
                        if (!aVar.c) {
                            diagramOverviewFragment4.U().n0(aVar.b.getAdapterPosition());
                            return;
                        }
                        h hVar = diagramOverviewFragment4.l;
                        if (hVar != null) {
                            DiagramOverviewActivity diagramOverviewActivity = (DiagramOverviewActivity) hVar;
                            Intrinsics.checkNotNullParameter(termData, "termData");
                            Intrinsics.checkNotNullParameter(termData, "termData");
                            diagramOverviewActivity.b0(termData);
                            diagramOverviewActivity.c0().J(3);
                            return;
                        }
                        return;
                    case 4:
                        com.quizlet.diagrams.a it4 = (com.quizlet.diagrams.a) obj;
                        Intrinsics.checkNotNullParameter(it4, "it");
                        h hVar2 = this.b.l;
                        if (hVar2 != null) {
                            Pair termData2 = it4.a;
                            DiagramOverviewActivity diagramOverviewActivity2 = (DiagramOverviewActivity) hVar2;
                            Intrinsics.checkNotNullParameter(termData2, "termData");
                            ((com.quizlet.quizletandroid.ui.common.adapter.presenter.e) diagramOverviewActivity2.f1.getValue()).c(diagramOverviewActivity2, diagramOverviewActivity2.m1, (DBTerm) termData2.a, O1.WORD, true);
                            return;
                        }
                        return;
                    default:
                        com.quizlet.diagrams.a it5 = (com.quizlet.diagrams.a) obj;
                        Intrinsics.checkNotNullParameter(it5, "it");
                        h hVar3 = this.b.l;
                        if (hVar3 != null) {
                            Pair termData3 = it5.a;
                            Intrinsics.checkNotNullParameter(termData3, "termData");
                            ((com.quizlet.quizletandroid.ui.common.adapter.presenter.e) ((DiagramOverviewActivity) hVar3).f1.getValue()).b((DBTerm) termData3.a, (DBSelectedTerm) termData3.b, 0);
                            return;
                        }
                        return;
                }
            }
        };
        final int i4 = 3;
        this.t = new io.reactivex.rxjava3.functions.d(this) { // from class: com.quizlet.quizletandroid.ui.diagramming.g
            public final /* synthetic */ DiagramOverviewFragment b;

            {
                this.b = this;
            }

            @Override // io.reactivex.rxjava3.functions.d
            public final void accept(Object obj) throws IOException {
                switch (i4) {
                    case 0:
                        DiagramData diagramData = (DiagramData) obj;
                        Intrinsics.checkNotNullParameter(diagramData, "diagramData");
                        DiagramOverviewFragment diagramOverviewFragment = this.b;
                        DiagramView setpageDiagramDiagramView = ((r) diagramOverviewFragment.J()).b;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDiagramView, "setpageDiagramDiagramView");
                        setpageDiagramDiagramView.d(diagramData, com.quizlet.diagrams.b.b);
                        com.quizlet.diagrams.e eVar = diagramOverviewFragment.m;
                        if (eVar != null) {
                            eVar.notifyDataSetChanged();
                            return;
                        } else {
                            Intrinsics.m("adapter");
                            throw null;
                        }
                    case 1:
                        List terms = (List) obj;
                        Intrinsics.checkNotNullParameter(terms, "terms");
                        DiagramOverviewFragment diagramOverviewFragment2 = this.b;
                        com.quizlet.diagrams.e eVar2 = diagramOverviewFragment2.m;
                        if (eVar2 == null) {
                            Intrinsics.m("adapter");
                            throw null;
                        }
                        Intrinsics.checkNotNullParameter(terms, "<set-?>");
                        eVar2.a = terms;
                        com.quizlet.diagrams.e eVar3 = diagramOverviewFragment2.m;
                        if (eVar3 == null) {
                            Intrinsics.m("adapter");
                            throw null;
                        }
                        eVar3.notifyDataSetChanged();
                        if (diagramOverviewFragment2.o == 0 || diagramOverviewFragment2.U().getVisibility() != 8) {
                            return;
                        }
                        com.quizlet.diagrams.e eVar4 = diagramOverviewFragment2.m;
                        if (eVar4 == null) {
                            Intrinsics.m("adapter");
                            throw null;
                        }
                        Iterator it2 = eVar4.a.iterator();
                        int i22 = 0;
                        while (true) {
                            if (it2.hasNext()) {
                                if (diagramOverviewFragment2.o != ((DBTerm) ((Pair) it2.next()).a).getId()) {
                                    i22++;
                                }
                            } else {
                                i22 = -1;
                            }
                        }
                        diagramOverviewFragment2.U().k0(i22);
                        diagramOverviewFragment2.U().setVisibility(0);
                        return;
                    case 2:
                        com.quizlet.diagrams.f fVar = (com.quizlet.diagrams.f) obj;
                        Intrinsics.checkNotNullParameter(fVar, "<destruct>");
                        long j = fVar.a;
                        DiagramOverviewFragment diagramOverviewFragment3 = this.b;
                        com.quizlet.diagrams.e eVar5 = diagramOverviewFragment3.m;
                        if (eVar5 == null) {
                            Intrinsics.m("adapter");
                            throw null;
                        }
                        Iterator it3 = eVar5.a.iterator();
                        int i32 = 0;
                        while (true) {
                            if (!it3.hasNext()) {
                                i32 = -1;
                            } else if (j != ((DBTerm) ((Pair) it3.next()).a).getId()) {
                                i32++;
                            }
                        }
                        int iQ1 = ((DiagramCardLayoutManager) diagramOverviewFragment3.n.getValue()).q1();
                        boolean z = diagramOverviewFragment3.U().getVisibility() == 8;
                        if (z) {
                            diagramOverviewFragment3.U().startAnimation(AnimationUtils.loadAnimation(diagramOverviewFragment3.getContext(), R.anim.slide_up));
                            diagramOverviewFragment3.U().setVisibility(0);
                        }
                        int i42 = iQ1 - i32;
                        diagramOverviewFragment3.V(j);
                        com.quizlet.diagrams.e eVar6 = diagramOverviewFragment3.m;
                        if (eVar6 == null) {
                            Intrinsics.m("adapter");
                            throw null;
                        }
                        if (eVar6.c != j) {
                            eVar6.c = j;
                            eVar6.notifyDataSetChanged();
                        }
                        if (Math.abs(i42) > 2 || z) {
                            diagramOverviewFragment3.U().k0(i32);
                            return;
                        } else {
                            diagramOverviewFragment3.U().n0(i32);
                            return;
                        }
                    case 3:
                        com.quizlet.diagrams.a aVar = (com.quizlet.diagrams.a) obj;
                        Intrinsics.checkNotNullParameter(aVar, "<destruct>");
                        Pair termData = aVar.a;
                        DiagramOverviewFragment diagramOverviewFragment4 = this.b;
                        if (!aVar.c) {
                            diagramOverviewFragment4.U().n0(aVar.b.getAdapterPosition());
                            return;
                        }
                        h hVar = diagramOverviewFragment4.l;
                        if (hVar != null) {
                            DiagramOverviewActivity diagramOverviewActivity = (DiagramOverviewActivity) hVar;
                            Intrinsics.checkNotNullParameter(termData, "termData");
                            Intrinsics.checkNotNullParameter(termData, "termData");
                            diagramOverviewActivity.b0(termData);
                            diagramOverviewActivity.c0().J(3);
                            return;
                        }
                        return;
                    case 4:
                        com.quizlet.diagrams.a it4 = (com.quizlet.diagrams.a) obj;
                        Intrinsics.checkNotNullParameter(it4, "it");
                        h hVar2 = this.b.l;
                        if (hVar2 != null) {
                            Pair termData2 = it4.a;
                            DiagramOverviewActivity diagramOverviewActivity2 = (DiagramOverviewActivity) hVar2;
                            Intrinsics.checkNotNullParameter(termData2, "termData");
                            ((com.quizlet.quizletandroid.ui.common.adapter.presenter.e) diagramOverviewActivity2.f1.getValue()).c(diagramOverviewActivity2, diagramOverviewActivity2.m1, (DBTerm) termData2.a, O1.WORD, true);
                            return;
                        }
                        return;
                    default:
                        com.quizlet.diagrams.a it5 = (com.quizlet.diagrams.a) obj;
                        Intrinsics.checkNotNullParameter(it5, "it");
                        h hVar3 = this.b.l;
                        if (hVar3 != null) {
                            Pair termData3 = it5.a;
                            Intrinsics.checkNotNullParameter(termData3, "termData");
                            ((com.quizlet.quizletandroid.ui.common.adapter.presenter.e) ((DiagramOverviewActivity) hVar3).f1.getValue()).b((DBTerm) termData3.a, (DBSelectedTerm) termData3.b, 0);
                            return;
                        }
                        return;
                }
            }
        };
        final int i5 = 4;
        this.u = new io.reactivex.rxjava3.functions.d(this) { // from class: com.quizlet.quizletandroid.ui.diagramming.g
            public final /* synthetic */ DiagramOverviewFragment b;

            {
                this.b = this;
            }

            @Override // io.reactivex.rxjava3.functions.d
            public final void accept(Object obj) throws IOException {
                switch (i5) {
                    case 0:
                        DiagramData diagramData = (DiagramData) obj;
                        Intrinsics.checkNotNullParameter(diagramData, "diagramData");
                        DiagramOverviewFragment diagramOverviewFragment = this.b;
                        DiagramView setpageDiagramDiagramView = ((r) diagramOverviewFragment.J()).b;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDiagramView, "setpageDiagramDiagramView");
                        setpageDiagramDiagramView.d(diagramData, com.quizlet.diagrams.b.b);
                        com.quizlet.diagrams.e eVar = diagramOverviewFragment.m;
                        if (eVar != null) {
                            eVar.notifyDataSetChanged();
                            return;
                        } else {
                            Intrinsics.m("adapter");
                            throw null;
                        }
                    case 1:
                        List terms = (List) obj;
                        Intrinsics.checkNotNullParameter(terms, "terms");
                        DiagramOverviewFragment diagramOverviewFragment2 = this.b;
                        com.quizlet.diagrams.e eVar2 = diagramOverviewFragment2.m;
                        if (eVar2 == null) {
                            Intrinsics.m("adapter");
                            throw null;
                        }
                        Intrinsics.checkNotNullParameter(terms, "<set-?>");
                        eVar2.a = terms;
                        com.quizlet.diagrams.e eVar3 = diagramOverviewFragment2.m;
                        if (eVar3 == null) {
                            Intrinsics.m("adapter");
                            throw null;
                        }
                        eVar3.notifyDataSetChanged();
                        if (diagramOverviewFragment2.o == 0 || diagramOverviewFragment2.U().getVisibility() != 8) {
                            return;
                        }
                        com.quizlet.diagrams.e eVar4 = diagramOverviewFragment2.m;
                        if (eVar4 == null) {
                            Intrinsics.m("adapter");
                            throw null;
                        }
                        Iterator it2 = eVar4.a.iterator();
                        int i22 = 0;
                        while (true) {
                            if (it2.hasNext()) {
                                if (diagramOverviewFragment2.o != ((DBTerm) ((Pair) it2.next()).a).getId()) {
                                    i22++;
                                }
                            } else {
                                i22 = -1;
                            }
                        }
                        diagramOverviewFragment2.U().k0(i22);
                        diagramOverviewFragment2.U().setVisibility(0);
                        return;
                    case 2:
                        com.quizlet.diagrams.f fVar = (com.quizlet.diagrams.f) obj;
                        Intrinsics.checkNotNullParameter(fVar, "<destruct>");
                        long j = fVar.a;
                        DiagramOverviewFragment diagramOverviewFragment3 = this.b;
                        com.quizlet.diagrams.e eVar5 = diagramOverviewFragment3.m;
                        if (eVar5 == null) {
                            Intrinsics.m("adapter");
                            throw null;
                        }
                        Iterator it3 = eVar5.a.iterator();
                        int i32 = 0;
                        while (true) {
                            if (!it3.hasNext()) {
                                i32 = -1;
                            } else if (j != ((DBTerm) ((Pair) it3.next()).a).getId()) {
                                i32++;
                            }
                        }
                        int iQ1 = ((DiagramCardLayoutManager) diagramOverviewFragment3.n.getValue()).q1();
                        boolean z = diagramOverviewFragment3.U().getVisibility() == 8;
                        if (z) {
                            diagramOverviewFragment3.U().startAnimation(AnimationUtils.loadAnimation(diagramOverviewFragment3.getContext(), R.anim.slide_up));
                            diagramOverviewFragment3.U().setVisibility(0);
                        }
                        int i42 = iQ1 - i32;
                        diagramOverviewFragment3.V(j);
                        com.quizlet.diagrams.e eVar6 = diagramOverviewFragment3.m;
                        if (eVar6 == null) {
                            Intrinsics.m("adapter");
                            throw null;
                        }
                        if (eVar6.c != j) {
                            eVar6.c = j;
                            eVar6.notifyDataSetChanged();
                        }
                        if (Math.abs(i42) > 2 || z) {
                            diagramOverviewFragment3.U().k0(i32);
                            return;
                        } else {
                            diagramOverviewFragment3.U().n0(i32);
                            return;
                        }
                    case 3:
                        com.quizlet.diagrams.a aVar = (com.quizlet.diagrams.a) obj;
                        Intrinsics.checkNotNullParameter(aVar, "<destruct>");
                        Pair termData = aVar.a;
                        DiagramOverviewFragment diagramOverviewFragment4 = this.b;
                        if (!aVar.c) {
                            diagramOverviewFragment4.U().n0(aVar.b.getAdapterPosition());
                            return;
                        }
                        h hVar = diagramOverviewFragment4.l;
                        if (hVar != null) {
                            DiagramOverviewActivity diagramOverviewActivity = (DiagramOverviewActivity) hVar;
                            Intrinsics.checkNotNullParameter(termData, "termData");
                            Intrinsics.checkNotNullParameter(termData, "termData");
                            diagramOverviewActivity.b0(termData);
                            diagramOverviewActivity.c0().J(3);
                            return;
                        }
                        return;
                    case 4:
                        com.quizlet.diagrams.a it4 = (com.quizlet.diagrams.a) obj;
                        Intrinsics.checkNotNullParameter(it4, "it");
                        h hVar2 = this.b.l;
                        if (hVar2 != null) {
                            Pair termData2 = it4.a;
                            DiagramOverviewActivity diagramOverviewActivity2 = (DiagramOverviewActivity) hVar2;
                            Intrinsics.checkNotNullParameter(termData2, "termData");
                            ((com.quizlet.quizletandroid.ui.common.adapter.presenter.e) diagramOverviewActivity2.f1.getValue()).c(diagramOverviewActivity2, diagramOverviewActivity2.m1, (DBTerm) termData2.a, O1.WORD, true);
                            return;
                        }
                        return;
                    default:
                        com.quizlet.diagrams.a it5 = (com.quizlet.diagrams.a) obj;
                        Intrinsics.checkNotNullParameter(it5, "it");
                        h hVar3 = this.b.l;
                        if (hVar3 != null) {
                            Pair termData3 = it5.a;
                            Intrinsics.checkNotNullParameter(termData3, "termData");
                            ((com.quizlet.quizletandroid.ui.common.adapter.presenter.e) ((DiagramOverviewActivity) hVar3).f1.getValue()).b((DBTerm) termData3.a, (DBSelectedTerm) termData3.b, 0);
                            return;
                        }
                        return;
                }
            }
        };
        final int i6 = 5;
        this.v = new io.reactivex.rxjava3.functions.d(this) { // from class: com.quizlet.quizletandroid.ui.diagramming.g
            public final /* synthetic */ DiagramOverviewFragment b;

            {
                this.b = this;
            }

            @Override // io.reactivex.rxjava3.functions.d
            public final void accept(Object obj) throws IOException {
                switch (i6) {
                    case 0:
                        DiagramData diagramData = (DiagramData) obj;
                        Intrinsics.checkNotNullParameter(diagramData, "diagramData");
                        DiagramOverviewFragment diagramOverviewFragment = this.b;
                        DiagramView setpageDiagramDiagramView = ((r) diagramOverviewFragment.J()).b;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDiagramView, "setpageDiagramDiagramView");
                        setpageDiagramDiagramView.d(diagramData, com.quizlet.diagrams.b.b);
                        com.quizlet.diagrams.e eVar = diagramOverviewFragment.m;
                        if (eVar != null) {
                            eVar.notifyDataSetChanged();
                            return;
                        } else {
                            Intrinsics.m("adapter");
                            throw null;
                        }
                    case 1:
                        List terms = (List) obj;
                        Intrinsics.checkNotNullParameter(terms, "terms");
                        DiagramOverviewFragment diagramOverviewFragment2 = this.b;
                        com.quizlet.diagrams.e eVar2 = diagramOverviewFragment2.m;
                        if (eVar2 == null) {
                            Intrinsics.m("adapter");
                            throw null;
                        }
                        Intrinsics.checkNotNullParameter(terms, "<set-?>");
                        eVar2.a = terms;
                        com.quizlet.diagrams.e eVar3 = diagramOverviewFragment2.m;
                        if (eVar3 == null) {
                            Intrinsics.m("adapter");
                            throw null;
                        }
                        eVar3.notifyDataSetChanged();
                        if (diagramOverviewFragment2.o == 0 || diagramOverviewFragment2.U().getVisibility() != 8) {
                            return;
                        }
                        com.quizlet.diagrams.e eVar4 = diagramOverviewFragment2.m;
                        if (eVar4 == null) {
                            Intrinsics.m("adapter");
                            throw null;
                        }
                        Iterator it2 = eVar4.a.iterator();
                        int i22 = 0;
                        while (true) {
                            if (it2.hasNext()) {
                                if (diagramOverviewFragment2.o != ((DBTerm) ((Pair) it2.next()).a).getId()) {
                                    i22++;
                                }
                            } else {
                                i22 = -1;
                            }
                        }
                        diagramOverviewFragment2.U().k0(i22);
                        diagramOverviewFragment2.U().setVisibility(0);
                        return;
                    case 2:
                        com.quizlet.diagrams.f fVar = (com.quizlet.diagrams.f) obj;
                        Intrinsics.checkNotNullParameter(fVar, "<destruct>");
                        long j = fVar.a;
                        DiagramOverviewFragment diagramOverviewFragment3 = this.b;
                        com.quizlet.diagrams.e eVar5 = diagramOverviewFragment3.m;
                        if (eVar5 == null) {
                            Intrinsics.m("adapter");
                            throw null;
                        }
                        Iterator it3 = eVar5.a.iterator();
                        int i32 = 0;
                        while (true) {
                            if (!it3.hasNext()) {
                                i32 = -1;
                            } else if (j != ((DBTerm) ((Pair) it3.next()).a).getId()) {
                                i32++;
                            }
                        }
                        int iQ1 = ((DiagramCardLayoutManager) diagramOverviewFragment3.n.getValue()).q1();
                        boolean z = diagramOverviewFragment3.U().getVisibility() == 8;
                        if (z) {
                            diagramOverviewFragment3.U().startAnimation(AnimationUtils.loadAnimation(diagramOverviewFragment3.getContext(), R.anim.slide_up));
                            diagramOverviewFragment3.U().setVisibility(0);
                        }
                        int i42 = iQ1 - i32;
                        diagramOverviewFragment3.V(j);
                        com.quizlet.diagrams.e eVar6 = diagramOverviewFragment3.m;
                        if (eVar6 == null) {
                            Intrinsics.m("adapter");
                            throw null;
                        }
                        if (eVar6.c != j) {
                            eVar6.c = j;
                            eVar6.notifyDataSetChanged();
                        }
                        if (Math.abs(i42) > 2 || z) {
                            diagramOverviewFragment3.U().k0(i32);
                            return;
                        } else {
                            diagramOverviewFragment3.U().n0(i32);
                            return;
                        }
                    case 3:
                        com.quizlet.diagrams.a aVar = (com.quizlet.diagrams.a) obj;
                        Intrinsics.checkNotNullParameter(aVar, "<destruct>");
                        Pair termData = aVar.a;
                        DiagramOverviewFragment diagramOverviewFragment4 = this.b;
                        if (!aVar.c) {
                            diagramOverviewFragment4.U().n0(aVar.b.getAdapterPosition());
                            return;
                        }
                        h hVar = diagramOverviewFragment4.l;
                        if (hVar != null) {
                            DiagramOverviewActivity diagramOverviewActivity = (DiagramOverviewActivity) hVar;
                            Intrinsics.checkNotNullParameter(termData, "termData");
                            Intrinsics.checkNotNullParameter(termData, "termData");
                            diagramOverviewActivity.b0(termData);
                            diagramOverviewActivity.c0().J(3);
                            return;
                        }
                        return;
                    case 4:
                        com.quizlet.diagrams.a it4 = (com.quizlet.diagrams.a) obj;
                        Intrinsics.checkNotNullParameter(it4, "it");
                        h hVar2 = this.b.l;
                        if (hVar2 != null) {
                            Pair termData2 = it4.a;
                            DiagramOverviewActivity diagramOverviewActivity2 = (DiagramOverviewActivity) hVar2;
                            Intrinsics.checkNotNullParameter(termData2, "termData");
                            ((com.quizlet.quizletandroid.ui.common.adapter.presenter.e) diagramOverviewActivity2.f1.getValue()).c(diagramOverviewActivity2, diagramOverviewActivity2.m1, (DBTerm) termData2.a, O1.WORD, true);
                            return;
                        }
                        return;
                    default:
                        com.quizlet.diagrams.a it5 = (com.quizlet.diagrams.a) obj;
                        Intrinsics.checkNotNullParameter(it5, "it");
                        h hVar3 = this.b.l;
                        if (hVar3 != null) {
                            Pair termData3 = it5.a;
                            Intrinsics.checkNotNullParameter(termData3, "termData");
                            ((com.quizlet.quizletandroid.ui.common.adapter.presenter.e) ((DiagramOverviewActivity) hVar3).f1.getValue()).b((DBTerm) termData3.a, (DBSelectedTerm) termData3.b, 0);
                            return;
                        }
                        return;
                }
            }
        };
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final String N() {
        return "DiagramOverviewFragment";
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final androidx.viewbinding.a O(LayoutInflater inflater, ViewGroup viewGroup) {
        Intrinsics.checkNotNullParameter(inflater, "inflater");
        View viewInflate = inflater.inflate(R.layout.diagram_overview_fragment, viewGroup, false);
        int i = R.id.setpage_diagram_diagram_view;
        DiagramView diagramView = (DiagramView) AbstractC3375o2.c(R.id.setpage_diagram_diagram_view, viewInflate);
        if (diagramView != null) {
            i = R.id.setpage_diagram_recycler_view;
            SnapRecyclerView snapRecyclerView = (SnapRecyclerView) AbstractC3375o2.c(R.id.setpage_diagram_recycler_view, viewInflate);
            if (snapRecyclerView != null) {
                r rVar = new r((RelativeLayout) viewInflate, diagramView, snapRecyclerView);
                Intrinsics.checkNotNullExpressionValue(rVar, "inflate(...)");
                return rVar;
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(viewInflate.getResources().getResourceName(i)));
    }

    public final o T() {
        o oVar = this.k;
        if (oVar != null) {
            return oVar;
        }
        Intrinsics.m("mainThreadScheduler");
        throw null;
    }

    public final SnapRecyclerView U() {
        SnapRecyclerView setpageDiagramRecyclerView = ((r) J()).c;
        Intrinsics.checkNotNullExpressionValue(setpageDiagramRecyclerView, "setpageDiagramRecyclerView");
        return setpageDiagramRecyclerView;
    }

    public final void V(long j) {
        DiagramView setpageDiagramDiagramView = ((r) J()).b;
        Intrinsics.checkNotNullExpressionValue(setpageDiagramDiagramView, "setpageDiagramDiagramView");
        long j2 = this.o;
        j presenter = setpageDiagramDiagramView.getPresenter();
        if (j2 != j) {
            presenter.e.remove(Long.valueOf(j2));
            presenter.e.add(Long.valueOf(j));
            String str = String.format("onDeselectTerm('%d');onSelectTerm('%d');", Arrays.copyOf(new Object[]{Long.valueOf(j2), Long.valueOf(j)}, 2));
            Intrinsics.checkNotNullExpressionValue(str, "format(...)");
            presenter.a(str);
        } else {
            presenter.getClass();
        }
        this.o = j;
    }

    @Override // androidx.fragment.app.Fragment
    public final void onActivityCreated(Bundle bundle) {
        super.onActivityCreated(bundle);
        this.o = bundle != null ? bundle.getLong("selected_term_id") : 0L;
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onDestroyView() {
        U().setAdapter(null);
        super.onDestroyView();
    }

    @Override // androidx.fragment.app.Fragment
    public final void onSaveInstanceState(Bundle outState) {
        Intrinsics.checkNotNullParameter(outState, "outState");
        outState.putLong("selected_term_id", this.o);
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onStart() {
        super.onStart();
        h hVar = this.l;
        io.reactivex.rxjava3.disposables.a aVar = this.p;
        com.quizlet.billing.subscriptions.c cVar = this.w;
        if (hVar != null) {
            DiagramOverviewActivity diagramOverviewActivity = (DiagramOverviewActivity) hVar;
            C4885d c4885dJ = diagramOverviewActivity.Y.j();
            com.quizlet.infra.legacysyncengine.models.serializers.a aVar2 = new com.quizlet.infra.legacysyncengine.models.serializers.a(18);
            p pVarN = p.n(diagramOverviewActivity.X, diagramOverviewActivity.W, diagramOverviewActivity.V, c4885dJ, aVar2);
            Intrinsics.checkNotNullExpressionValue(pVarN, "zip(...)");
            A7.a(pVarN.h(T()).i(this.q, cVar), aVar);
        }
        h hVar2 = this.l;
        io.reactivex.rxjava3.internal.functions.b bVar = io.reactivex.rxjava3.internal.functions.d.c;
        if (hVar2 != null) {
            io.reactivex.rxjava3.subjects.d dVar = ((DiagramOverviewActivity) hVar2).Y;
            dVar.getClass();
            C4887f c4887f = new C4887f(dVar, 2);
            Intrinsics.checkNotNullExpressionValue(c4887f, "hide(...)");
            A7.a(c4887f.s(T()).u(this.r, cVar, bVar), aVar);
        }
        DiagramView setpageDiagramDiagramView = ((r) J()).b;
        Intrinsics.checkNotNullExpressionValue(setpageDiagramDiagramView, "setpageDiagramDiagramView");
        io.reactivex.rxjava3.disposables.b bVarU = setpageDiagramDiagramView.getTermClicks().s(T()).u(this.s, cVar, bVar);
        Intrinsics.checkNotNullExpressionValue(bVarU, "subscribe(...)");
        A7.a(bVarU, aVar);
        com.quizlet.diagrams.e eVar = this.m;
        if (eVar == null) {
            Intrinsics.m("adapter");
            throw null;
        }
        io.reactivex.rxjava3.subjects.j jVar = eVar.f;
        jVar.getClass();
        C4887f c4887f2 = new C4887f(jVar, 2);
        Intrinsics.checkNotNullExpressionValue(c4887f2, "hide(...)");
        io.reactivex.rxjava3.disposables.b bVarU2 = c4887f2.s(T()).u(this.t, cVar, bVar);
        Intrinsics.checkNotNullExpressionValue(bVarU2, "subscribe(...)");
        A7.a(bVarU2, aVar);
        com.quizlet.diagrams.e eVar2 = this.m;
        if (eVar2 == null) {
            Intrinsics.m("adapter");
            throw null;
        }
        io.reactivex.rxjava3.subjects.j jVar2 = eVar2.d;
        jVar2.getClass();
        C4887f c4887f3 = new C4887f(jVar2, 2);
        Intrinsics.checkNotNullExpressionValue(c4887f3, "hide(...)");
        io.reactivex.rxjava3.disposables.b bVarU3 = c4887f3.s(T()).u(this.u, cVar, bVar);
        Intrinsics.checkNotNullExpressionValue(bVarU3, "subscribe(...)");
        A7.a(bVarU3, aVar);
        com.quizlet.diagrams.e eVar3 = this.m;
        if (eVar3 == null) {
            Intrinsics.m("adapter");
            throw null;
        }
        io.reactivex.rxjava3.subjects.j jVar3 = eVar3.e;
        jVar3.getClass();
        C4887f c4887f4 = new C4887f(jVar3, 2);
        Intrinsics.checkNotNullExpressionValue(c4887f4, "hide(...)");
        io.reactivex.rxjava3.disposables.b bVarU4 = c4887f4.s(T()).u(this.v, cVar, bVar);
        Intrinsics.checkNotNullExpressionValue(bVarU4, "subscribe(...)");
        A7.a(bVarU4, aVar);
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onStop() {
        this.p.d();
        super.onStop();
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onViewCreated(View view, Bundle bundle) {
        Intrinsics.checkNotNullParameter(view, "view");
        super.onViewCreated(view, bundle);
        com.google.mlkit.vision.documentscanner.internal.c cVar = this.j;
        if (cVar == null) {
            Intrinsics.m("adapterFactory");
            throw null;
        }
        K terms = K.a;
        Intrinsics.checkNotNullParameter(terms, "terms");
        this.m = new com.quizlet.diagrams.e(terms, (com.quizlet.qutils.image.loading.a) cVar.b);
        U().setLayoutManager((DiagramCardLayoutManager) this.n.getValue());
        SnapRecyclerView snapRecyclerViewU = U();
        com.quizlet.diagrams.e eVar = this.m;
        if (eVar == null) {
            Intrinsics.m("adapter");
            throw null;
        }
        snapRecyclerViewU.setAdapter(eVar);
        U().k(this.x);
    }
}

package com.quizlet.explanations.solution.viewmodel;

import androidx.collection.C0208f;
import androidx.lifecycle.X;
import androidx.lifecycle.Y;
import androidx.lifecycle.p0;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3409x1;
import com.quizlet.data.model.SimpleImage;
import com.quizlet.data.model.Solution;
import com.quizlet.data.model.SolutionColumn;
import com.quizlet.data.model.SolutionColumnImage;
import com.quizlet.data.model.SolutionColumnImages;
import com.quizlet.data.model.SolutionStep;
import com.quizlet.eventlogger.features.explanations.ExplanationsLogger;
import com.quizlet.explanations.solution.data.g;
import com.quizlet.explanations.solution.data.h;
import com.quizlet.explanations.solution.data.i;
import java.util.ArrayList;
import java.util.List;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.collections.A;
import kotlin.collections.B;
import kotlin.collections.C;
import kotlin.collections.CollectionsKt;
import kotlin.collections.K;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes2.dex */
public final class b extends com.quizlet.viewmodel.b {
    public final ExplanationsLogger c;
    public final Y d;
    public final Y e;
    public final X f;
    public final Y g;
    public final X h;
    public final X i;
    public final ArrayList j;
    public int k;
    public final C0208f l;
    public com.google.mlkit.common.model.a m;

    public b(ExplanationsLogger explanationsLogger) {
        Intrinsics.checkNotNullParameter(explanationsLogger, "explanationsLogger");
        this.c = explanationsLogger;
        this.d = new Y();
        this.e = new Y();
        this.f = new X(1);
        Y y = new Y();
        this.g = y;
        this.h = p0.k(y, a.a);
        this.i = new X(1);
        this.j = new ArrayList();
        this.l = new C0208f(0);
    }

    public final ExplanationsLogger.EventData B() {
        com.google.mlkit.common.model.a aVar = this.m;
        if (aVar == null) {
            Intrinsics.m("solutionMetadata");
            throw null;
        }
        if (aVar instanceof g) {
            g gVar = (g) aVar;
            return new ExplanationsLogger.EventData.Exercise(gVar.a, gVar.b, gVar.c);
        }
        if (!(aVar instanceof h)) {
            throw new NoWhenBranchMatchedException();
        }
        h hVar = (h) aVar;
        return new ExplanationsLogger.EventData.Question(hVar.a, hVar.b);
    }

    public final void C(i data) {
        Intrinsics.checkNotNullParameter(data, "data");
        this.m = data.getMetadata();
        E(data.b(), data.c());
    }

    public final void D(int i, boolean z) {
        b bVar;
        Object objB;
        this.k = i;
        C0208f c0208f = this.l;
        Integer numValueOf = Integer.valueOf(i);
        Object obj = c0208f.get(numValueOf);
        if (obj == null) {
            obj = 1;
            c0208f.put(numValueOf, obj);
        }
        int iIntValue = ((Number) obj).intValue();
        ArrayList arrayList = this.j;
        List list = (List) ((i < 0 || i >= arrayList.size()) ? K.a : arrayList.get(i));
        this.e.j(new e(CollectionsKt.p0(list, iIntValue), z));
        if (iIntValue >= list.size()) {
            objB = K.a;
            bVar = this;
        } else {
            bVar = this;
            objB = A.b(new com.quizlet.explanations.solution.recyclerview.revealbutton.b(new androidx.activity.K(0, bVar, b.class, "onShowAllSteps", "onShowAllSteps()V", 0, 20)));
        }
        bVar.g.j(objB);
    }

    public final void E(List list, boolean z) {
        b bVar;
        ArrayList arrayList = this.j;
        arrayList.clear();
        int i = 10;
        List listP0 = CollectionsKt.p0(list, 10);
        com.quizlet.explanations.solution.fragments.b onImageLongClick = new com.quizlet.explanations.solution.fragments.b(1, this, b.class, "onImageLongClick", "onImageLongClick(Lcom/quizlet/explanations/solution/recyclerview/step/LongClickTarget;)V", 0, 6);
        Intrinsics.checkNotNullParameter(listP0, "<this>");
        Intrinsics.checkNotNullParameter(onImageLongClick, "onImageLongClick");
        ArrayList arrayList2 = new ArrayList();
        int i2 = 0;
        for (Object obj : listP0) {
            int i3 = i2 + 1;
            if (i2 < 0) {
                B.p();
                throw null;
            }
            Solution solution = (Solution) obj;
            ArrayList arrayList3 = new ArrayList();
            boolean z2 = true;
            int i4 = solution.b;
            List list2 = solution.a;
            ArrayList arrayList4 = new ArrayList(C.q(list2, i));
            int i5 = 0;
            for (Object obj2 : list2) {
                int i6 = i5;
                i5 = i6 + 1;
                if (i6 < 0) {
                    B.p();
                    throw null;
                }
                SolutionStep solutionStep = (SolutionStep) obj2;
                Intrinsics.checkNotNullParameter(solutionStep, "<this>");
                Intrinsics.checkNotNullParameter(onImageLongClick, "onImageLongClick");
                ArrayList arrayList5 = arrayList3;
                boolean z3 = solutionStep.a;
                List<SolutionColumn> list3 = solutionStep.c;
                ArrayList arrayList6 = new ArrayList(C.q(list3, i));
                for (SolutionColumn solutionColumn : list3) {
                    Intrinsics.checkNotNullParameter(solutionColumn, "<this>");
                    com.quizlet.explanations.solution.fragments.b bVar2 = onImageLongClick;
                    String str = solutionColumn.a;
                    boolean z4 = z3;
                    boolean z5 = !solutionColumn.b;
                    int i7 = i5;
                    SolutionColumnImages solutionColumnImages = solutionColumn.c;
                    int i8 = i4;
                    SolutionColumnImage solutionColumnImage = solutionColumnImages.a;
                    SimpleImage simpleImage = solutionColumnImage != null ? solutionColumnImage.a : null;
                    SolutionColumnImage solutionColumnImage2 = solutionColumnImages.b;
                    arrayList6.add(new com.quizlet.explanations.solution.recyclerview.step.c(str, z5, new com.quizlet.explanations.solution.recyclerview.step.d(simpleImage, solutionColumnImage2 != null ? solutionColumnImage2.b : null)));
                    onImageLongClick = bVar2;
                    z3 = z4;
                    i5 = i7;
                    i4 = i8;
                }
                com.quizlet.explanations.solution.fragments.b bVar3 = onImageLongClick;
                ArrayList arrayList7 = arrayList4;
                onImageLongClick = bVar3;
                arrayList7.add(new com.quizlet.explanations.solution.recyclerview.step.e(z3, i5, i4, AbstractC3409x1.i(arrayList6), i3, bVar3, z));
                arrayList4 = arrayList7;
                arrayList3 = arrayList5;
                z2 = true;
                i = 10;
            }
            ArrayList arrayList8 = arrayList3;
            arrayList8.addAll(arrayList4);
            arrayList2.add(arrayList8);
            i2 = i3;
            i = 10;
        }
        arrayList.addAll(arrayList2);
        int size = arrayList.size();
        Y y = this.d;
        if (size > 1) {
            bVar = this;
            y.j(A.b(new com.quizlet.explanations.solution.recyclerview.tablayout.b(size, new com.quizlet.explanations.solution.fragments.b(1, bVar, b.class, "onTabSelected", "onTabSelected(I)V", 0, 5))));
        } else {
            bVar = this;
            y.j(K.a);
        }
        bVar.D(bVar.k, false);
    }
}

package com.quizlet.explanations.textbook.chaptermenu.viewmodel;

import androidx.lifecycle.X;
import androidx.lifecycle.Y;
import com.quizlet.data.model.Exercise;
import com.quizlet.data.model.ExerciseGroup;
import com.quizlet.data.model.InterfaceC4138j0;
import com.quizlet.data.model.InterfaceC4141k0;
import com.quizlet.data.model.Section;
import com.quizlet.data.model.TableOfContentItem;
import com.quizlet.explanations.textbook.chaptermenu.recyclerview.c;
import com.quizlet.explanations.textbook.chaptermenu.recyclerview.d;
import com.quizlet.explanations.textbook.chaptermenu.recyclerview.i;
import java.util.ArrayList;
import java.util.List;
import kotlin.Metadata;
import kotlin.collections.C;
import kotlin.collections.K;

@Metadata
/* loaded from: classes2.dex */
public final class b extends com.quizlet.viewmodel.a {
    public final X d = new X(1);
    public final Y e = new Y();

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r2v3, types: [kotlin.collections.K] */
    /* JADX WARN: Type inference failed for: r2v4, types: [java.util.Collection] */
    /* JADX WARN: Type inference failed for: r2v6, types: [java.util.ArrayList] */
    /* JADX WARN: Type inference failed for: r31v0, types: [com.quizlet.data.model.TableOfContentItem] */
    /* JADX WARN: Type inference failed for: r5v0, types: [kotlin.collections.K] */
    /* JADX WARN: Type inference failed for: r5v1, types: [java.util.Collection] */
    /* JADX WARN: Type inference failed for: r5v2, types: [java.util.ArrayList] */
    public final void B(TableOfContentItem tableOfContentItem) {
        ?? arrayList;
        ?? arrayList2;
        List<Exercise> listA;
        List<TableOfContentItem> listD;
        com.quizlet.baserecyclerview.a dVar;
        ArrayList arrayList3 = new ArrayList();
        InterfaceC4138j0 interfaceC4138j0 = tableOfContentItem instanceof InterfaceC4138j0 ? (InterfaceC4138j0) tableOfContentItem : null;
        if (interfaceC4138j0 == null || (listD = interfaceC4138j0.d()) == null) {
            arrayList = K.a;
        } else {
            arrayList = new ArrayList(C.q(listD, 10));
            for (TableOfContentItem tableOfContentItem2 : listD) {
                if (tableOfContentItem2 instanceof Section) {
                    Section section = (Section) tableOfContentItem2;
                    long j = section.a;
                    String str = section.c;
                    String str2 = str == null ? "" : str;
                    String str3 = section.d;
                    dVar = new i(j, str2, str3 == null ? "" : str3, section, section.b, new com.quizlet.explanations.solution.fragments.b(1, this, b.class, "onChapterMenuClick", "onChapterMenuClick(Lcom/quizlet/data/model/TableOfContentItem;)V", 0, 7));
                } else {
                    if (!(tableOfContentItem2 instanceof ExerciseGroup)) {
                        throw new IllegalStateException("Not a valid one for now");
                    }
                    ExerciseGroup exerciseGroup = (ExerciseGroup) tableOfContentItem2;
                    dVar = new d(exerciseGroup.a, exerciseGroup.d, exerciseGroup.c, exerciseGroup, exerciseGroup.b, new com.quizlet.explanations.solution.fragments.b(1, this, b.class, "onChapterMenuClick", "onChapterMenuClick(Lcom/quizlet/data/model/TableOfContentItem;)V", 0, 8));
                }
                arrayList.add(dVar);
            }
        }
        InterfaceC4141k0 interfaceC4141k0 = tableOfContentItem != 0 ? (InterfaceC4141k0) tableOfContentItem : null;
        if (interfaceC4141k0 == null || (listA = interfaceC4141k0.a()) == null) {
            arrayList2 = K.a;
        } else {
            arrayList2 = new ArrayList(C.q(listA, 10));
            for (Exercise exercise : listA) {
                arrayList2.add(new c(exercise.a, exercise.b, exercise.c, exercise.d, new com.quizlet.explanations.solution.fragments.b(1, this, b.class, "onExerciseClick", "onExerciseClick(Ljava/lang/String;)V", 0, 9)));
            }
        }
        arrayList3.addAll(arrayList);
        arrayList3.addAll(arrayList2);
        this.e.j(arrayList3);
    }
}

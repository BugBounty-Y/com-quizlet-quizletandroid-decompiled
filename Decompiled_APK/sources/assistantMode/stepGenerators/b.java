package assistantMode.stepGenerators;

import androidx.compose.animation.d0;
import androidx.compose.runtime.internal.j;
import assistantMode.enums.EnumC1450d;
import assistantMode.enums.k;
import assistantMode.enums.w;
import assistantMode.enums.y;
import assistantMode.grading.d;
import assistantMode.refactored.types.Checkpoint;
import assistantMode.refactored.types.FillInTheBlankQuestionStudiableMetadata;
import assistantMode.refactored.types.MultipleChoiceSelectAllThatApplyQuestionStudiableMetadata;
import assistantMode.refactored.types.Task;
import assistantMode.refactored.types.TaskProgress;
import assistantMode.refactored.types.TaskQuestionTypeProgress;
import assistantMode.refactored.types.TaskWithProgress;
import assistantMode.tasks.sequencing.e;
import assistantMode.types.B;
import assistantMode.types.C1454a;
import assistantMode.types.C1455b;
import assistantMode.types.C1457d;
import assistantMode.types.C1459f;
import assistantMode.types.NormalizedOptions;
import assistantMode.types.RoundResultItem;
import assistantMode.types.aliases.ExperimentConfiguration;
import assistantMode.types.i;
import assistantMode.types.o;
import assistantMode.types.p;
import assistantMode.types.q;
import assistantMode.types.v;
import assistantMode.utils.f;
import assistantMode.utils.h;
import com.google.android.gms.internal.mlkit_vision_barcode.W4;
import com.google.android.gms.internal.mlkit_vision_camera.O2;
import com.google.android.gms.internal.mlkit_vision_camera.Q2;
import com.google.android.gms.internal.mlkit_vision_camera.Y2;
import com.google.android.gms.internal.mlkit_vision_camera.a3;
import com.quizlet.data.repository.course.membership.c;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Pair;
import kotlin.collections.A;
import kotlin.collections.C;
import kotlin.collections.CollectionsKt;
import kotlin.collections.G;
import kotlin.collections.K;
import kotlin.collections.V;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class b implements assistantMode.refactored.interfaces.b {
    public final y a;
    public final NormalizedOptions b;
    public final h c;
    public final w d;
    public final boolean e;
    public final ExperimentConfiguration f;
    public final NormalizedOptions g;
    public final ArrayList h;
    public c i;
    public d j;
    public final j k;
    public final androidx.collection.internal.b l;
    public final Set m;
    public final ArrayList n;
    public final ArrayList o;
    public final List p;
    public final List q;
    public final LinkedHashMap r;
    public Task s;
    public assistantMode.tasks.progress.b t;
    public assistantMode.tasks.sequencing.d u;
    public assistantMode.stepGenerators.types.b v;

    /* JADX WARN: Code restructure failed: missing block: B:448:0x0bc4, code lost:
    
        r18 = r7;
        r17 = r10;
        r7 = r27;
     */
    /* JADX WARN: Code restructure failed: missing block: B:53:0x01eb, code lost:
    
        r1.add(r13);
     */
    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:260:0x07b4  */
    /* JADX WARN: Removed duplicated region for block: B:354:0x09df  */
    /* JADX WARN: Removed duplicated region for block: B:356:0x09e7  */
    /* JADX WARN: Removed duplicated region for block: B:358:0x09ee  */
    /* JADX WARN: Removed duplicated region for block: B:484:0x0c5f  */
    /* JADX WARN: Removed duplicated region for block: B:486:0x0c67  */
    /* JADX WARN: Removed duplicated region for block: B:487:0x0c6e  */
    /* JADX WARN: Removed duplicated region for block: B:489:0x0c72  */
    /* JADX WARN: Removed duplicated region for block: B:490:0x0c7a  */
    /* JADX WARN: Type inference failed for: r0v24 */
    /* JADX WARN: Type inference failed for: r0v25, types: [assistantMode.refactored.types.h] */
    /* JADX WARN: Type inference failed for: r0v74 */
    /* JADX WARN: Type inference failed for: r2v45, types: [java.lang.Object, java.util.Map] */
    /* JADX WARN: Type inference failed for: r3v40 */
    /* JADX WARN: Type inference failed for: r3v44, types: [boolean] */
    /* JADX WARN: Type inference failed for: r3v47 */
    /* JADX WARN: Type inference failed for: r4v36 */
    /* JADX WARN: Type inference failed for: r4v37, types: [boolean] */
    /* JADX WARN: Type inference failed for: r4v40 */
    /* JADX WARN: Type inference failed for: r8v31 */
    /* JADX WARN: Type inference failed for: r8v32, types: [java.util.Map] */
    /* JADX WARN: Type inference failed for: r8v62 */
    /* JADX WARN: Type inference failed for: r9v103 */
    /* JADX WARN: Type inference failed for: r9v31, types: [assistantMode.tasks.progress.b] */
    /* JADX WARN: Type inference failed for: r9v34 */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public b(java.util.List r32, assistantMode.enums.y r33, assistantMode.types.NormalizedOptions r34, assistantMode.utils.h r35, assistantMode.enums.w r36, assistantMode.enums.C r37, boolean r38, assistantMode.types.aliases.ExperimentConfiguration r39) throws java.lang.Throwable {
        /*
            Method dump skipped, instructions count: 3670
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: assistantMode.stepGenerators.b.<init>(java.util.List, assistantMode.enums.y, assistantMode.types.NormalizedOptions, assistantMode.utils.h, assistantMode.enums.w, assistantMode.enums.C, boolean, assistantMode.types.aliases.ExperimentConfiguration):void");
    }

    @Override // assistantMode.refactored.interfaces.b
    public final Object a(v vVar, grading.core.d dVar, com.quizlet.quizletandroid.ui.studymodes.assistant.studyengine.a aVar) {
        d dVar2 = this.j;
        if (dVar2 != null) {
            return dVar2.a(vVar, dVar2.b(dVar), aVar);
        }
        throw new IllegalStateException("No grader available. Be sure to generate a question before grading it");
    }

    @Override // assistantMode.refactored.interfaces.b
    public final Y2 b(List newAnswers, boolean z) {
        ArrayList arrayList;
        Object next;
        p b;
        e eVar;
        assistantMode.stepGenerators.types.c cVarF;
        Object next2;
        k kVar;
        Intrinsics.checkNotNullParameter(newAnswers, "studyHistorySinceLastStep");
        G.u(this.h, newAnswers);
        assistantMode.stepGenerators.types.b bVar = this.v;
        if (bVar != null && (kVar = bVar.c) != null && !newAnswers.isEmpty()) {
            Iterator it2 = newAnswers.iterator();
            while (it2.hasNext()) {
                C1455b answer = (C1455b) it2.next();
                k kVarC = W4.c(kVar);
                androidx.collection.internal.b bVar2 = this.l;
                bVar2.getClass();
                Intrinsics.checkNotNullParameter(answer, "answer");
                LinkedHashMap linkedHashMap = bVar2.a;
                List listY0 = (List) linkedHashMap.get(Long.valueOf(answer.e));
                if (listY0 == null) {
                    listY0 = CollectionsKt.y0(K.a);
                }
                listY0.add(answer);
                long j = answer.e;
                linkedHashMap.put(Long.valueOf(j), listY0);
                assistantMode.tasks.progress.b bVar3 = (assistantMode.tasks.progress.b) this.r.get(this.s);
                if (bVar3 != null) {
                    bVar3.a(answer, kVarC);
                }
                if (answer.a) {
                    this.u.f(A.b(new q(j, kVarC)));
                }
            }
        }
        LinkedHashMap linkedHashMap2 = this.r;
        List list = this.q;
        Task taskB = a3.b(linkedHashMap2, list);
        assistantMode.types.w wVarG = this.u.g();
        c cVar = this.i;
        if (cVar == null) {
            cVar = new c(wVarG, this.c, this.n);
        }
        this.i = cVar;
        double dG = g();
        com.quizlet.data.repository.classfolder.e eVar2 = (com.quizlet.data.repository.classfolder.e) cVar.c;
        if (dG < 100.0d || this.v != null) {
            Intrinsics.checkNotNullParameter(newAnswers, "newAnswers");
            eVar2.getClass();
            Intrinsics.checkNotNullParameter(newAnswers, "newAnswers");
            Iterator it3 = newAnswers.iterator();
            while (true) {
                boolean zHasNext = it3.hasNext();
                arrayList = (ArrayList) eVar2.d;
                if (!zHasNext) {
                    break;
                }
                C1455b c1455b = (C1455b) it3.next();
                eVar2.c = CollectionsKt.n0(CollectionsKt.d0((List) eVar2.c, c1455b), new androidx.constraintlayout.core.e(16));
                Iterator it4 = arrayList.iterator();
                while (true) {
                    if (!it4.hasNext()) {
                        next2 = null;
                        break;
                    }
                    next2 = it4.next();
                    if (((C1459f) ((Pair) next2).a).a == c1455b.e) {
                        break;
                    }
                }
                Pair pair = (Pair) next2;
                if (pair != null) {
                    arrayList.remove(pair);
                    if (!c1455b.a && !arrayList.isEmpty()) {
                        if (c1455b.d != k.b) {
                            arrayList.add(pair);
                        }
                    }
                }
            }
            Pair pair2 = (Pair) CollectionsKt.firstOrNull(arrayList);
            if (pair2 == null) {
                eVar = null;
            } else {
                C1459f questionSpec = (C1459f) pair2.a;
                k kVar2 = (k) pair2.b;
                Iterator it5 = ((ArrayList) cVar.b).iterator();
                while (true) {
                    if (!it5.hasNext()) {
                        next = null;
                        break;
                    }
                    next = it5.next();
                    if (((C1454a) next).a.a == questionSpec.a) {
                        break;
                    }
                }
                C1454a card = (C1454a) next;
                if (card == null) {
                    throw new Error(d0.n(questionSpec.a, "Could not find studiable item id "));
                }
                Intrinsics.checkNotNullParameter(questionSpec, "questionSpec");
                h studyableMaterialDataSource = (h) cVar.a;
                Intrinsics.checkNotNullParameter(studyableMaterialDataSource, "studyableMaterialDataSource");
                Intrinsics.checkNotNullParameter(card, "card");
                C1457d c1457d = new C1457d(card, questionSpec.b, questionSpec.c);
                k kVar3 = k.l;
                assistantMode.types.G g = card.a;
                k kVar4 = questionSpec.d;
                if (kVar4 == kVar3) {
                    FillInTheBlankQuestionStudiableMetadata fillInTheBlankQuestionStudiableMetadataE = studyableMaterialDataSource.e(c1457d);
                    if (fillInTheBlankQuestionStudiableMetadataE == null) {
                        throw new IllegalStateException(d0.n(g.a, "Eligible question for Fill In The Blank Question expected: "));
                    }
                    b = new assistantMode.types.j(fillInTheBlankQuestionStudiableMetadataE, c1457d);
                } else if (kVar4 == k.n) {
                    ArrayList arrayListD = studyableMaterialDataSource.d(c1457d);
                    if (arrayListD.isEmpty()) {
                        throw new IllegalStateException(d0.n(g.a, "Eligible question for Fill In The Blank Multiple Choice Question expected: "));
                    }
                    b = new i(arrayListD, c1457d);
                } else if (kVar4 == k.m) {
                    MultipleChoiceSelectAllThatApplyQuestionStudiableMetadata multipleChoiceSelectAllThatApplyQuestionStudiableMetadataG = studyableMaterialDataSource.g(c1457d);
                    if (multipleChoiceSelectAllThatApplyQuestionStudiableMetadataG == null) {
                        throw new IllegalStateException(d0.n(g.a, "Eligible question for Multiple Choice Select All That Apply Question expected: "));
                    }
                    b = new o(multipleChoiceSelectAllThatApplyQuestionStudiableMetadataG, c1457d);
                } else {
                    b = new B(c1457d);
                }
                Q2 q2B = O2.b(kVar4, b, studyableMaterialDataSource, z);
                eVar = new e(q2B.d(), q2B.c(), kVar2);
            }
            if (eVar != null) {
                cVarF = e(eVar.a, eVar2, eVar.c, eVar.b);
            } else {
                assistantMode.tasks.progress.b bVar4 = this.t;
                boolean zD = bVar4 != null ? bVar4.d() : false;
                assistantMode.stepGenerators.types.b bVar5 = this.v;
                Task task = bVar5 == null ? (Task) CollectionsKt.L(this.q) : bVar5.g;
                if (task != null) {
                    int iIndexOf = list.indexOf(task);
                    if (zD) {
                        List list2 = this.p;
                        if (iIndexOf < list2.size() - 1) {
                        }
                    }
                }
                cVarF = f(eVar2, task == null);
            }
        } else {
            cVarF = f(eVar2, false);
        }
        if (!Intrinsics.b(taskB, this.s)) {
            this.u = d(taskB, this.b.a);
        }
        this.s = taskB;
        assistantMode.stepGenerators.types.b bVar6 = cVarF.a;
        if (bVar6.b != null) {
            this.i = null;
        }
        this.j = cVarF.b;
        this.v = bVar6;
        this.t = taskB != null ? (assistantMode.tasks.progress.b) V.d(taskB, this.r) : null;
        return bVar6;
    }

    @Override // assistantMode.refactored.interfaces.b
    public final boolean c() {
        return false;
    }

    /* JADX WARN: Removed duplicated region for block: B:8:0x0019  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final assistantMode.tasks.sequencing.d d(assistantMode.refactored.types.Task r7, java.util.List r8) {
        /*
            r6 = this;
            if (r7 != 0) goto L43
            assistantMode.tasks.sequencing.c r7 = new assistantMode.tasks.sequencing.c
            androidx.collection.internal.b r0 = r6.l
            androidx.compose.runtime.internal.j r1 = r6.k
            assistantMode.enums.k r2 = assistantMode.enums.k.b
            boolean r3 = r8.contains(r2)
            if (r3 == 0) goto L11
            goto L3f
        L11:
            assistantMode.enums.k r3 = assistantMode.enums.k.f
            boolean r4 = r8.contains(r3)
            if (r4 == 0) goto L1b
        L19:
            r2 = r3
            goto L3f
        L1b:
            assistantMode.enums.k r4 = assistantMode.enums.k.d
            boolean r5 = r8.contains(r4)
            if (r5 == 0) goto L25
            r2 = r4
            goto L3f
        L25:
            assistantMode.enums.k r4 = assistantMode.enums.k.l
            boolean r4 = r8.contains(r4)
            if (r4 == 0) goto L2e
            goto L3f
        L2e:
            assistantMode.enums.k r2 = assistantMode.enums.k.n
            boolean r4 = r8.contains(r2)
            if (r4 == 0) goto L37
            goto L3f
        L37:
            assistantMode.enums.k r2 = assistantMode.enums.k.m
            boolean r8 = r8.contains(r2)
            if (r8 == 0) goto L19
        L3f:
            r7.<init>(r0, r1, r2)
            return r7
        L43:
            com.quizlet.data.repository.folderset.c r8 = new com.quizlet.data.repository.folderset.c
            androidx.compose.runtime.internal.j r0 = r6.k
            java.util.ArrayList r1 = r6.o
            boolean r2 = r6.e
            r8.<init>(r7, r1, r0, r2)
            return r8
        */
        throw new UnsupportedOperationException("Method not decompiled: assistantMode.stepGenerators.b.d(assistantMode.refactored.types.Task, java.util.List):assistantMode.tasks.sequencing.d");
    }

    public final assistantMode.stepGenerators.types.c e(assistantMode.refactored.types.e eVar, com.quizlet.data.repository.classfolder.e eVar2, k kVar, d dVar) {
        double d;
        assistantMode.refactored.types.d dVar2;
        Checkpoint checkpoint;
        double dG = g();
        assistantMode.tasks.progress.b bVar = this.t;
        if (bVar != null) {
            bVar.b().getClass();
            d = (r3.a / r3.b) * 100;
        } else {
            d = 100.0d;
        }
        boolean z = eVar instanceof assistantMode.refactored.types.d;
        if (z) {
            dVar2 = (assistantMode.refactored.types.d) eVar;
        } else {
            if (!(eVar instanceof Checkpoint)) {
                throw new NoWhenBranchMatchedException();
            }
            dVar2 = null;
        }
        if (z) {
            checkpoint = null;
        } else {
            if (!(eVar instanceof Checkpoint)) {
                throw new NoWhenBranchMatchedException();
            }
            checkpoint = (Checkpoint) eVar;
        }
        List<C1455b> list = (List) eVar2.c;
        int i = 0;
        if (list == null || !list.isEmpty()) {
            for (C1455b answer : list) {
                List list2 = f.a;
                Intrinsics.checkNotNullParameter(answer, "answer");
                if (answer.a || f.a.contains(answer.d)) {
                    i++;
                    if (i < 0) {
                        kotlin.collections.B.o();
                        throw null;
                    }
                }
            }
        }
        int size = ((assistantMode.types.w) eVar2.b).a.size();
        return new assistantMode.stepGenerators.types.c(new assistantMode.stepGenerators.types.b(dVar2, checkpoint, kVar, Integer.valueOf(i), Double.valueOf((i / size) * 100.0d), Integer.valueOf(size), this.s, d, dG), dVar);
    }

    public final assistantMode.stepGenerators.types.c f(com.quizlet.data.repository.classfolder.e eVar, boolean z) {
        double dG = g();
        List list = (List) eVar.c;
        LinkedHashMap linkedHashMap = new LinkedHashMap();
        for (Object obj : list) {
            Long lValueOf = Long.valueOf(((C1455b) obj).e);
            Object arrayList = linkedHashMap.get(lValueOf);
            if (arrayList == null) {
                arrayList = new ArrayList();
                linkedHashMap.put(lValueOf, arrayList);
            }
            ((List) arrayList).add(obj);
        }
        Collection collectionValues = linkedHashMap.values();
        ArrayList arrayList2 = new ArrayList(C.q(collectionValues, 10));
        Iterator it2 = collectionValues.iterator();
        while (true) {
            Object next = null;
            if (!it2.hasNext()) {
                break;
            }
            Iterator it3 = ((List) it2.next()).iterator();
            if (it3.hasNext()) {
                next = it3.next();
                if (it3.hasNext()) {
                    long j = ((C1455b) next).f;
                    do {
                        Object next2 = it3.next();
                        long j2 = ((C1455b) next2).f;
                        if (j > j2) {
                            next = next2;
                            j = j2;
                        }
                    } while (it3.hasNext());
                }
            }
            Intrinsics.d(next);
            arrayList2.add((C1455b) next);
        }
        List<C1455b> listN0 = CollectionsKt.n0(arrayList2, new androidx.constraintlayout.core.e(17));
        ArrayList arrayList3 = new ArrayList(C.q(listN0, 10));
        for (C1455b c1455b : listN0) {
            arrayList3.add(new RoundResultItem(c1455b.e, c1455b.a));
        }
        return e(new Checkpoint(z ? EnumC1450d.d : dG >= 100.0d ? EnumC1450d.c : EnumC1450d.b, dG >= 100.0d, arrayList3, null), eVar, null, null);
    }

    public final double g() {
        ArrayList arrayListH = h();
        Intrinsics.checkNotNullParameter(arrayListH, "<this>");
        ArrayList arrayList = new ArrayList(C.q(arrayListH, 10));
        Iterator it2 = arrayListH.iterator();
        while (it2.hasNext()) {
            Map map = ((TaskWithProgress) it2.next()).a;
            Set setKeySet = map.keySet();
            ArrayList arrayList2 = new ArrayList(C.q(setKeySet, 10));
            Iterator it3 = setKeySet.iterator();
            while (it3.hasNext()) {
                Object obj = map.get((k) it3.next());
                if (obj == null) {
                    throw new IllegalStateException("Required value was null.");
                }
                arrayList2.add(Integer.valueOf(((TaskQuestionTypeProgress) obj).a));
            }
            int iO0 = CollectionsKt.o0(arrayList2);
            Set setKeySet2 = map.keySet();
            ArrayList arrayList3 = new ArrayList(C.q(setKeySet2, 10));
            Iterator it4 = setKeySet2.iterator();
            while (it4.hasNext()) {
                Object obj2 = map.get((k) it4.next());
                if (obj2 == null) {
                    throw new IllegalStateException("Required value was null.");
                }
                arrayList3.add(Integer.valueOf(((TaskQuestionTypeProgress) obj2).b));
            }
            arrayList.add(new TaskProgress(iO0, CollectionsKt.o0(arrayList3)));
        }
        ArrayList arrayList4 = new ArrayList(C.q(arrayList, 10));
        Iterator it5 = arrayList.iterator();
        while (it5.hasNext()) {
            arrayList4.add(Integer.valueOf(((TaskProgress) it5.next()).a));
        }
        int iO02 = CollectionsKt.o0(arrayList4);
        ArrayList arrayList5 = new ArrayList(C.q(arrayList, 10));
        Iterator it6 = arrayList.iterator();
        while (it6.hasNext()) {
            arrayList5.add(Integer.valueOf(((TaskProgress) it6.next()).b));
        }
        return (iO02 / CollectionsKt.o0(arrayList5)) * 100;
    }

    public final ArrayList h() {
        List<Task> list = this.q;
        ArrayList arrayList = new ArrayList(C.q(list, 10));
        for (Task task : list) {
            Object obj = this.r.get(task);
            if (obj == null) {
                throw new IllegalStateException((task + " must have progress data in TaskGenerator.getTasksWithProgress").toString());
            }
            arrayList.add(new TaskWithProgress(task, (assistantMode.tasks.progress.b) obj));
        }
        return arrayList;
    }
}

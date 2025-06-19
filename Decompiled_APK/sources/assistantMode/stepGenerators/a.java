package assistantMode.stepGenerators;

import androidx.constraintlayout.core.e;
import assistantMode.enums.EnumC1450d;
import assistantMode.enums.k;
import assistantMode.enums.m;
import assistantMode.grading.d;
import assistantMode.refactored.types.AndroidWriteMasteryBuckets;
import assistantMode.refactored.types.Checkpoint;
import assistantMode.refactored.types.IosWriteMasteryBuckets;
import assistantMode.refactored.types.SpellMasteryBuckets;
import assistantMode.refactored.types.WebWriteMasteryBuckets;
import assistantMode.refactored.types.WrittenQuestion;
import assistantMode.refactored.types.c;
import assistantMode.types.C1454a;
import assistantMode.types.C1455b;
import assistantMode.types.C1457d;
import assistantMode.types.NormalizedOptions;
import assistantMode.types.RoundResultItem;
import assistantMode.types.v;
import assistantMode.types.y;
import assistantMode.utils.h;
import com.google.android.gms.internal.mlkit_vision_camera.O2;
import com.google.android.gms.internal.mlkit_vision_camera.Q2;
import com.google.android.gms.internal.mlkit_vision_camera.X2;
import com.google.android.gms.internal.mlkit_vision_camera.Y2;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import kotlin.NoWhenBranchMatchedException;
import kotlin.collections.A;
import kotlin.collections.B;
import kotlin.collections.C;
import kotlin.collections.CollectionsKt;
import kotlin.collections.K;
import kotlin.collections.U;
import kotlin.jvm.internal.Intrinsics;
import kotlin.n;

/* loaded from: classes.dex */
public final class a implements assistantMode.refactored.interfaces.b {
    public final h a;
    public final y b;
    public final NormalizedOptions c;
    public final List d;
    public final ArrayList e;
    public d f;
    public final k g;
    public final m h;
    public final m i;
    public final com.google.android.gms.cloudmessaging.k j;
    public ArrayList k;
    public ArrayList l;
    public ArrayList m;
    public int n;

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r1v38, types: [java.util.List] */
    /* JADX WARN: Type inference failed for: r6v26, types: [java.util.ArrayList] */
    /* JADX WARN: Type inference failed for: r6v27, types: [kotlin.collections.K] */
    /* JADX WARN: Type inference failed for: r6v4, types: [java.lang.Iterable, java.util.List] */
    /* JADX WARN: Type inference failed for: r6v5 */
    /* JADX WARN: Type inference failed for: r6v6, types: [java.util.Collection] */
    public a(h studyableMaterialDataSource, NormalizedOptions options, List initialAnswers, y sequencingConfiguration) throws Exception {
        ?? N0;
        ?? P0;
        Object next;
        Intrinsics.checkNotNullParameter(studyableMaterialDataSource, "studyableMaterialDataSource");
        Intrinsics.checkNotNullParameter(options, "options");
        Intrinsics.checkNotNullParameter(initialAnswers, "initialAnswers");
        Intrinsics.checkNotNullParameter(sequencingConfiguration, "sequencingConfiguration");
        this.a = studyableMaterialDataSource;
        this.b = sequencingConfiguration;
        this.c = options;
        this.d = A.c(studyableMaterialDataSource.a);
        ArrayList arrayList = new ArrayList(C.q(initialAnswers, 10));
        Iterator it2 = initialAnswers.iterator();
        while (it2.hasNext()) {
            arrayList.add(((C1455b) it2.next()).a());
        }
        ArrayList arrayListY0 = CollectionsKt.y0(arrayList);
        this.e = arrayListY0;
        this.g = (k) CollectionsKt.L(this.c.a);
        this.h = (m) CollectionsKt.L(this.c.b);
        this.i = (m) CollectionsKt.L(this.c.c);
        LinkedHashSet linkedHashSet = new LinkedHashSet();
        LinkedHashSet linkedHashSet2 = new LinkedHashSet();
        LinkedHashSet linkedHashSet3 = new LinkedHashSet();
        List listN0 = CollectionsKt.n0(arrayListY0, new e(13));
        LinkedHashMap linkedHashMap = new LinkedHashMap();
        for (Object obj : listN0) {
            Long lValueOf = Long.valueOf(((C1455b) obj).e);
            Object arrayList2 = linkedHashMap.get(lValueOf);
            if (arrayList2 == null) {
                arrayList2 = new ArrayList();
                linkedHashMap.put(lValueOf, arrayList2);
            }
            ((List) arrayList2).add(obj);
        }
        for (C1454a c1454a : this.d) {
            List list = (List) linkedHashMap.get(Long.valueOf(c1454a.a.a));
            list = list == null ? K.a : list;
            Iterator it3 = list.iterator();
            int size = 0;
            while (true) {
                if (!it3.hasNext()) {
                    size = -1;
                    break;
                } else if (!((C1455b) it3.next()).a) {
                    break;
                } else {
                    size++;
                }
            }
            size = size == -1 ? list.size() : size;
            if (size >= 2) {
                linkedHashSet3.add(c1454a);
            } else if (size != 1) {
                linkedHashSet.add(c1454a);
            } else if (d() > 1) {
                linkedHashSet2.add(c1454a);
            } else {
                linkedHashSet3.add(c1454a);
            }
        }
        this.j = new com.google.android.gms.cloudmessaging.k(linkedHashSet, linkedHashSet2, linkedHashSet3, d());
        Intrinsics.checkNotNullParameter(initialAnswers, "initialAnswers");
        Integer numF = f();
        if (numF == null) {
            Intrinsics.checkNotNullParameter(initialAnswers, "initialAnswers");
            LinkedHashMap linkedHashMap2 = new LinkedHashMap();
            for (Object obj2 : initialAnswers) {
                Long lValueOf2 = Long.valueOf(((C1455b) obj2).e);
                Object arrayList3 = linkedHashMap2.get(lValueOf2);
                if (arrayList3 == null) {
                    arrayList3 = new ArrayList();
                    linkedHashMap2.put(lValueOf2, arrayList3);
                }
                ((List) arrayList3).add(obj2);
            }
            LinkedHashMap linkedHashMap3 = new LinkedHashMap(U.a(linkedHashMap2.size()));
            for (Map.Entry entry : linkedHashMap2.entrySet()) {
                linkedHashMap3.put(entry.getKey(), Integer.valueOf(((List) entry.getValue()).size()));
            }
            Integer num = (Integer) CollectionsKt.W(linkedHashMap3.values());
            int iIntValue = num != null ? num.intValue() : 0;
            LinkedHashMap linkedHashMap4 = new LinkedHashMap();
            for (Map.Entry entry2 : linkedHashMap3.entrySet()) {
                if (((Number) entry2.getValue()).intValue() == iIntValue) {
                    linkedHashMap4.put(entry2.getKey(), entry2.getValue());
                }
            }
            Set setA0 = CollectionsKt.A0(linkedHashMap4.keySet());
            LinkedHashMap linkedHashMap5 = new LinkedHashMap();
            for (Map.Entry entry3 : linkedHashMap2.entrySet()) {
                if (setA0.contains(Long.valueOf(((Number) entry3.getKey()).longValue()))) {
                    linkedHashMap5.put(entry3.getKey(), entry3.getValue());
                }
            }
            Collection collectionValues = linkedHashMap5.values();
            N0 = new ArrayList(C.q(collectionValues, 10));
            Iterator it4 = collectionValues.iterator();
            while (it4.hasNext()) {
                Iterator it5 = ((List) it4.next()).iterator();
                if (it5.hasNext()) {
                    next = it5.next();
                    if (it5.hasNext()) {
                        long j = ((C1455b) next).f;
                        do {
                            Object next2 = it5.next();
                            long j2 = ((C1455b) next2).f;
                            if (j < j2) {
                                next = next2;
                                j = j2;
                            }
                        } while (it5.hasNext());
                    }
                } else {
                    next = null;
                }
                Intrinsics.d(next);
                N0.add((C1455b) next);
            }
            ArrayList arrayListG = g(initialAnswers);
            ArrayList arrayList4 = new ArrayList();
            Iterator it6 = arrayListG.iterator();
            while (it6.hasNext()) {
                Object next3 = it6.next();
                if (!setA0.contains(Long.valueOf(((C1454a) next3).a.a))) {
                    arrayList4.add(next3);
                }
            }
            if (arrayList4.isEmpty()) {
                N0 = K.a;
            }
        } else {
            int iIntValue2 = numF.intValue();
            Intrinsics.checkNotNullParameter(initialAnswers, "initialAnswers");
            N0 = CollectionsKt.n0(initialAnswers, new e(12));
            LinkedHashSet linkedHashSet4 = new LinkedHashSet();
            List list2 = this.d;
            ArrayList arrayList5 = new ArrayList(C.q(list2, 10));
            Iterator it7 = list2.iterator();
            while (it7.hasNext()) {
                arrayList5.add(Long.valueOf(((C1454a) it7.next()).a.a));
            }
            LinkedHashSet linkedHashSetZ0 = CollectionsKt.z0(arrayList5);
            LinkedHashMap linkedHashMap6 = new LinkedHashMap();
            Integer numValueOf = null;
            int i = 0;
            for (Object obj3 : N0) {
                int i2 = i + 1;
                if (i < 0) {
                    B.p();
                    throw null;
                }
                C1455b c1455b = (C1455b) obj3;
                int i3 = i;
                linkedHashSet4.add(Long.valueOf(c1455b.e));
                boolean z = c1455b.a;
                long j3 = c1455b.e;
                if (z) {
                    Integer num2 = (Integer) linkedHashMap6.get(Long.valueOf(j3));
                    int iIntValue3 = (num2 != null ? num2.intValue() : 0) + 1;
                    linkedHashMap6.put(Long.valueOf(j3), Integer.valueOf(iIntValue3));
                    if (iIntValue3 >= d()) {
                        linkedHashSetZ0.remove(Long.valueOf(j3));
                    }
                } else {
                    linkedHashMap6.put(Long.valueOf(j3), 0);
                }
                if (linkedHashSet4.size() == iIntValue2 || linkedHashSetZ0.equals(linkedHashSet4)) {
                    linkedHashSet4.clear();
                    numValueOf = Integer.valueOf(i3);
                }
                i = i2;
            }
            if (numValueOf != null) {
                List listQ0 = CollectionsKt.q0(N0.size() - (numValueOf.intValue() + 1), N0);
                if (listQ0 != null) {
                    N0 = listQ0;
                }
            }
        }
        ArrayList arrayListY02 = CollectionsKt.y0(N0);
        this.k = arrayListY02;
        ArrayList arrayListG2 = g(this.e);
        ArrayList arrayList6 = new ArrayList(C.q(arrayListY02, 10));
        Iterator it8 = arrayListY02.iterator();
        while (it8.hasNext()) {
            arrayList6.add(Long.valueOf(((C1455b) it8.next()).e));
        }
        Set setA02 = CollectionsKt.A0(arrayList6);
        ArrayList arrayList7 = new ArrayList();
        Iterator it9 = arrayListG2.iterator();
        while (it9.hasNext()) {
            Object next4 = it9.next();
            if (!setA02.contains(Long.valueOf(((C1454a) next4).a.a))) {
                arrayList7.add(next4);
            }
        }
        Integer numF2 = f();
        if (numF2 != null && (P0 = CollectionsKt.p0(arrayList7, numF2.intValue() - arrayListY02.size())) != 0) {
            arrayList7 = P0;
        }
        this.l = CollectionsKt.y0(arrayList7);
        ArrayList arrayList8 = this.k;
        ArrayList arrayList9 = new ArrayList();
        Iterator it10 = arrayList8.iterator();
        while (it10.hasNext()) {
            Object next5 = it10.next();
            if (!((C1455b) next5).a) {
                arrayList9.add(next5);
            }
        }
        ArrayList arrayList10 = new ArrayList(C.q(arrayList9, 10));
        Iterator it11 = arrayList9.iterator();
        while (it11.hasNext()) {
            arrayList10.add(Long.valueOf(((C1455b) it11.next()).e));
        }
        ArrayList arrayList11 = new ArrayList();
        for (Object obj4 : this.d) {
            if (arrayList10.contains(Long.valueOf(((C1454a) obj4).a.a))) {
                arrayList11.add(obj4);
            }
        }
        this.m = CollectionsKt.y0(arrayList11);
        this.n = this.l.size() + this.k.size();
        if (this.b == y.b) {
            Intrinsics.checkNotNullParameter("Learn sequencing not supported. Use AssistantGenerator", "message");
            throw new n("Learn sequencing not supported. Use AssistantGenerator");
        }
        if (this.c.a.size() > 1) {
            Intrinsics.checkNotNullParameter("More than one question type at a time not supported", "message");
            throw new n("More than one question type at a time not supported");
        }
        if (this.c.b.size() > 1) {
            Intrinsics.checkNotNullParameter("More than one prompt side at a time not supported", "message");
            throw new n("More than one prompt side at a time not supported");
        }
        if (this.c.c.size() <= 1) {
            return;
        }
        Intrinsics.checkNotNullParameter("More than one answer side at a time not supported", "message");
        throw new n("More than one answer side at a time not supported");
    }

    @Override // assistantMode.refactored.interfaces.b
    public final Object a(v vVar, grading.core.d dVar, com.quizlet.quizletandroid.ui.studymodes.assistant.studyengine.a aVar) {
        d dVar2 = this.f;
        if (dVar2 != null) {
            return dVar2.a(vVar, dVar2.b(dVar), aVar);
        }
        throw new IllegalStateException("No grader available. Be sure to generate a question before grading it");
    }

    @Override // assistantMode.refactored.interfaces.b
    public final Y2 b(List studyHistorySinceLastStep, boolean z) throws Exception {
        c webWriteMasteryBuckets;
        Integer num;
        Intrinsics.checkNotNullParameter(studyHistorySinceLastStep, "studyHistorySinceLastStep");
        boolean zIsEmpty = studyHistorySinceLastStep.isEmpty();
        ArrayList arrayList = this.e;
        com.google.android.gms.cloudmessaging.k kVar = this.j;
        y yVar = this.b;
        if (!zIsEmpty) {
            if (studyHistorySinceLastStep.size() > 1) {
                throw new IllegalArgumentException("Pass only one answer at a time");
            }
            C1455b c1455b = (C1455b) CollectionsKt.L(studyHistorySinceLastStep);
            arrayList.add(c1455b);
            this.k.add(c1455b);
            if (c1455b.e != ((C1454a) CollectionsKt.L(this.l)).a.a) {
                long j = ((C1454a) CollectionsKt.L(this.l)).a.a;
                ArrayList arrayList2 = new ArrayList(C.q(studyHistorySinceLastStep, 10));
                Iterator it2 = studyHistorySinceLastStep.iterator();
                while (it2.hasNext()) {
                    arrayList2.add(Double.valueOf(((C1455b) it2.next()).e));
                }
                Double[] dArr = (Double[]) arrayList2.toArray(new Double[0]);
                ArrayList arrayList3 = this.l;
                ArrayList arrayList4 = new ArrayList(C.q(arrayList3, 10));
                Iterator it3 = arrayList3.iterator();
                while (it3.hasNext()) {
                    arrayList4.add(Double.valueOf(((C1454a) it3.next()).a.a));
                }
                Double[] dArr2 = (Double[]) arrayList4.toArray(new Double[0]);
                ArrayList arrayList5 = this.m;
                ArrayList arrayList6 = new ArrayList(C.q(arrayList5, 10));
                Iterator it4 = arrayList5.iterator();
                while (it4.hasNext()) {
                    arrayList6.add(Double.valueOf(((C1454a) it4.next()).a.a));
                }
                Double[] dArr3 = (Double[]) arrayList6.toArray(new Double[0]);
                ArrayList arrayList7 = this.k;
                ArrayList arrayList8 = new ArrayList(C.q(arrayList7, 10));
                Iterator it5 = arrayList7.iterator();
                while (it5.hasNext()) {
                    arrayList8.add(Double.valueOf(((C1455b) it5.next()).e));
                }
                throw new assistantMode.exceptions.a(dArr, dArr2, dArr3, (Double[]) arrayList8.toArray(new Double[0]));
            }
            C1454a card = (C1454a) this.l.remove(0);
            if (c1455b.a) {
                kVar.getClass();
                Intrinsics.checkNotNullParameter(card, "card");
                LinkedHashSet linkedHashSet = (LinkedHashSet) kVar.c;
                boolean zContains = linkedHashSet.contains(card);
                LinkedHashSet linkedHashSet2 = (LinkedHashSet) kVar.e;
                LinkedHashSet linkedHashSet3 = (LinkedHashSet) kVar.d;
                int i = kVar.b;
                if (zContains) {
                    linkedHashSet.remove(card);
                    if (i > 1) {
                        linkedHashSet3.add(card);
                    } else {
                        linkedHashSet2.add(card);
                    }
                } else if (i > 1 && linkedHashSet3.contains(card)) {
                    linkedHashSet3.remove(card);
                    linkedHashSet2.add(card);
                }
            } else {
                this.m.add(card);
                kVar.getClass();
                Intrinsics.checkNotNullParameter(card, "card");
                if (((LinkedHashSet) kVar.e).contains(card)) {
                    throw new IllegalArgumentException("Card can't become unfinished after finishing");
                }
                ((LinkedHashSet) kVar.c).add(card);
                ((LinkedHashSet) kVar.d).remove(card);
            }
        } else if (this.l.isEmpty()) {
            ArrayList arrayList9 = new ArrayList();
            y yVar2 = y.f;
            if (yVar != yVar2) {
                arrayList9.addAll(this.m);
            }
            this.m = new ArrayList();
            Integer numF = f();
            if (yVar != yVar2) {
                X2.a(arrayList9, (LinkedHashSet) kVar.c, numF);
                if (d() > 1) {
                    X2.a(arrayList9, (LinkedHashSet) kVar.d, numF);
                }
            } else {
                ArrayList arrayListY0 = CollectionsKt.y0((LinkedHashSet) kVar.c);
                if (d() > 1) {
                    arrayListY0.addAll((LinkedHashSet) kVar.d);
                }
                X2.a(arrayList9, arrayListY0, numF);
            }
            this.n = arrayList9.size();
            this.l = CollectionsKt.y0(A.c(arrayList9));
        }
        ArrayList arrayList10 = this.k;
        ArrayList arrayList11 = new ArrayList(C.q(arrayList10, 10));
        Iterator it6 = arrayList10.iterator();
        while (it6.hasNext()) {
            arrayList11.add(Long.valueOf(((C1455b) it6.next()).e));
        }
        Set setA0 = CollectionsKt.A0(arrayList11);
        int iOrdinal = yVar.ordinal();
        if (iOrdinal == 0) {
            throw new IllegalStateException("Learn mode not supported by SimpleStepGenerator");
        }
        if (iOrdinal == 1) {
            ArrayList arrayList12 = this.l;
            ArrayList arrayList13 = new ArrayList(C.q(arrayList12, 10));
            Iterator it7 = arrayList12.iterator();
            while (it7.hasNext()) {
                arrayList13.add(Long.valueOf(((C1454a) it7.next()).a.a));
            }
            ArrayList arrayList14 = new ArrayList();
            Iterator it8 = arrayList13.iterator();
            while (it8.hasNext()) {
                Object next = it8.next();
                if (!setA0.contains(Long.valueOf(((Number) next).longValue()))) {
                    arrayList14.add(next);
                }
            }
            ArrayList arrayList15 = this.m;
            ArrayList arrayList16 = new ArrayList(C.q(arrayList15, 10));
            Iterator it9 = arrayList15.iterator();
            while (it9.hasNext()) {
                arrayList16.add(Long.valueOf(((C1454a) it9.next()).a.a));
            }
            LinkedHashSet linkedHashSet4 = (LinkedHashSet) kVar.e;
            ArrayList arrayList17 = new ArrayList(C.q(linkedHashSet4, 10));
            Iterator it10 = linkedHashSet4.iterator();
            while (it10.hasNext()) {
                arrayList17.add(Long.valueOf(((C1454a) it10.next()).a.a));
            }
            webWriteMasteryBuckets = new WebWriteMasteryBuckets(arrayList14, arrayList16, arrayList17);
        } else if (iOrdinal == 2) {
            LinkedHashSet linkedHashSet5 = (LinkedHashSet) kVar.c;
            ArrayList arrayList18 = new ArrayList(C.q(linkedHashSet5, 10));
            Iterator it11 = linkedHashSet5.iterator();
            while (it11.hasNext()) {
                arrayList18.add(Long.valueOf(((C1454a) it11.next()).a.a));
            }
            LinkedHashSet linkedHashSet6 = (LinkedHashSet) kVar.e;
            ArrayList arrayList19 = new ArrayList(C.q(linkedHashSet6, 10));
            Iterator it12 = linkedHashSet6.iterator();
            while (it12.hasNext()) {
                arrayList19.add(Long.valueOf(((C1454a) it12.next()).a.a));
            }
            webWriteMasteryBuckets = new AndroidWriteMasteryBuckets(arrayList18, arrayList19);
        } else if (iOrdinal == 3) {
            LinkedHashSet linkedHashSet7 = (LinkedHashSet) kVar.c;
            ArrayList arrayList20 = new ArrayList(C.q(linkedHashSet7, 10));
            Iterator it13 = linkedHashSet7.iterator();
            while (it13.hasNext()) {
                arrayList20.add(Long.valueOf(((C1454a) it13.next()).a.a));
            }
            LinkedHashSet linkedHashSet8 = (LinkedHashSet) kVar.d;
            ArrayList arrayList21 = new ArrayList(C.q(linkedHashSet8, 10));
            Iterator it14 = linkedHashSet8.iterator();
            while (it14.hasNext()) {
                arrayList21.add(Long.valueOf(((C1454a) it14.next()).a.a));
            }
            LinkedHashSet linkedHashSet9 = (LinkedHashSet) kVar.e;
            ArrayList arrayList22 = new ArrayList(C.q(linkedHashSet9, 10));
            Iterator it15 = linkedHashSet9.iterator();
            while (it15.hasNext()) {
                arrayList22.add(Long.valueOf(((C1454a) it15.next()).a.a));
            }
            webWriteMasteryBuckets = new IosWriteMasteryBuckets(arrayList20, arrayList21, arrayList22);
        } else {
            if (iOrdinal != 4) {
                throw new NoWhenBranchMatchedException();
            }
            LinkedHashSet linkedHashSet10 = (LinkedHashSet) kVar.c;
            ArrayList arrayList23 = new ArrayList(C.q(linkedHashSet10, 10));
            Iterator it16 = linkedHashSet10.iterator();
            while (it16.hasNext()) {
                arrayList23.add(Long.valueOf(((C1454a) it16.next()).a.a));
            }
            LinkedHashSet linkedHashSet11 = (LinkedHashSet) kVar.d;
            ArrayList arrayList24 = new ArrayList(C.q(linkedHashSet11, 10));
            Iterator it17 = linkedHashSet11.iterator();
            while (it17.hasNext()) {
                arrayList24.add(Long.valueOf(((C1454a) it17.next()).a.a));
            }
            LinkedHashSet linkedHashSet12 = (LinkedHashSet) kVar.e;
            ArrayList arrayList25 = new ArrayList(C.q(linkedHashSet12, 10));
            Iterator it18 = linkedHashSet12.iterator();
            while (it18.hasNext()) {
                arrayList25.add(Long.valueOf(((C1454a) it18.next()).a.a));
            }
            webWriteMasteryBuckets = new SpellMasteryBuckets(arrayList23, arrayList24, arrayList25);
        }
        c cVar = webWriteMasteryBuckets;
        if (!this.l.isEmpty()) {
            Q2 q2B = O2.b(this.g, new assistantMode.types.B(new C1457d((C1454a) CollectionsKt.L(this.l), this.h, this.i)), this.a, false);
            this.f = q2B.c();
            assistantMode.refactored.types.d dVarD = q2B.d();
            if (dVarD instanceof WrittenQuestion) {
                dVarD = WrittenQuestion.b((WrittenQuestion) dVarD);
            }
            return new assistantMode.stepGenerators.types.a(dVarD, null, e(), cVar, Integer.valueOf(this.n - this.l.size()), Integer.valueOf(this.n), 6);
        }
        ArrayList answersSinceRoundStart = this.k;
        Intrinsics.checkNotNullParameter(answersSinceRoundStart, "answersSinceRoundStart");
        LinkedHashMap linkedHashMap = new LinkedHashMap();
        Iterator it19 = answersSinceRoundStart.iterator();
        while (it19.hasNext()) {
            Object next2 = it19.next();
            Long lValueOf = Long.valueOf(((C1455b) next2).e);
            Object arrayList26 = linkedHashMap.get(lValueOf);
            if (arrayList26 == null) {
                arrayList26 = new ArrayList();
                linkedHashMap.put(lValueOf, arrayList26);
            }
            ((List) arrayList26).add(next2);
        }
        Collection collectionValues = linkedHashMap.values();
        ArrayList arrayList27 = new ArrayList(C.q(collectionValues, 10));
        Iterator it20 = collectionValues.iterator();
        while (true) {
            num = null;
            Object next3 = null;
            num = null;
            num = null;
            if (!it20.hasNext()) {
                break;
            }
            Iterator it21 = ((List) it20.next()).iterator();
            if (it21.hasNext()) {
                next3 = it21.next();
                if (it21.hasNext()) {
                    long j2 = ((C1455b) next3).f;
                    do {
                        Object next4 = it21.next();
                        long j3 = ((C1455b) next4).f;
                        if (j2 > j3) {
                            j2 = j3;
                            next3 = next4;
                        }
                    } while (it21.hasNext());
                }
            }
            Intrinsics.d(next3);
            arrayList27.add((C1455b) next3);
        }
        List<C1455b> listN0 = CollectionsKt.n0(arrayList27, new e(10));
        ArrayList arrayList28 = new ArrayList(C.q(listN0, 10));
        for (C1455b c1455b2 : listN0) {
            arrayList28.add(new RoundResultItem(c1455b2.e, c1455b2.a));
        }
        this.k = new ArrayList();
        double dE = e();
        boolean z2 = dE == 100.0d;
        int iOrdinal2 = yVar.ordinal();
        if (iOrdinal2 == 0) {
            throw new Exception("SimpleStepGenerator does not support Learn");
        }
        if (iOrdinal2 == 1) {
            LinkedHashMap linkedHashMap2 = new LinkedHashMap();
            Iterator it22 = arrayList.iterator();
            while (it22.hasNext()) {
                Object next5 = it22.next();
                Long lValueOf2 = Long.valueOf(((C1455b) next5).e);
                Object arrayList29 = linkedHashMap2.get(lValueOf2);
                if (arrayList29 == null) {
                    arrayList29 = new ArrayList();
                    linkedHashMap2.put(lValueOf2, arrayList29);
                }
                ((List) arrayList29).add(next5);
            }
            ArrayList arrayList30 = new ArrayList(linkedHashMap2.size());
            Iterator it23 = linkedHashMap2.entrySet().iterator();
            while (it23.hasNext()) {
                arrayList30.add(Integer.valueOf(((List) ((Map.Entry) it23.next()).getValue()).size()));
            }
            Comparable comparableW = CollectionsKt.W(arrayList30);
            if (comparableW == null) {
                throw new IllegalStateException("Cannot generate a checkpoint if no answers have been submitted");
            }
            num = (Integer) comparableW;
        } else if (iOrdinal2 != 2 && iOrdinal2 != 3 && iOrdinal2 != 4) {
            throw new NoWhenBranchMatchedException();
        }
        return new assistantMode.stepGenerators.types.a(null, new Checkpoint(dE >= 100.0d ? EnumC1450d.c : EnumC1450d.b, z2, arrayList28, num), e(), cVar, Integer.valueOf(this.n - this.l.size()), Integer.valueOf(this.n), 5);
    }

    @Override // assistantMode.refactored.interfaces.b
    public final boolean c() {
        return true;
    }

    public final int d() {
        y yVar = y.e;
        y yVar2 = this.b;
        return (yVar2 == yVar || yVar2 == y.f) ? 2 : 1;
    }

    public final double e() {
        int size;
        int size2;
        int iD = d();
        List list = this.d;
        com.google.android.gms.cloudmessaging.k kVar = this.j;
        if (iD > 1) {
            size = list.size() * 2;
            size2 = ((LinkedHashSet) kVar.d).size() + (((LinkedHashSet) kVar.e).size() * 2);
        } else {
            size = list.size();
            size2 = ((LinkedHashSet) kVar.e).size();
        }
        return (size2 * 100.0d) / size;
    }

    public final Integer f() throws Exception {
        int iOrdinal = this.b.ordinal();
        if (iOrdinal == 0) {
            throw new Exception("SimpleStepGenerator does not support Learn");
        }
        if (iOrdinal == 1) {
            return null;
        }
        if (iOrdinal == 2 || iOrdinal == 3 || iOrdinal == 4) {
            return 7;
        }
        throw new NoWhenBranchMatchedException();
    }

    public final ArrayList g(List list) {
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
        int iD = d();
        ArrayList arrayList2 = new ArrayList();
        for (Object obj2 : this.d) {
            Iterable iterable = (List) linkedHashMap.get(Long.valueOf(((C1454a) obj2).a.a));
            if (iterable == null) {
                iterable = K.a;
            }
            List listQ0 = CollectionsKt.q0(iD, CollectionsKt.n0(iterable, new e(11)));
            int i = 0;
            if (listQ0 == null || !listQ0.isEmpty()) {
                Iterator it2 = listQ0.iterator();
                while (it2.hasNext()) {
                    if (((C1455b) it2.next()).a && (i = i + 1) < 0) {
                        B.o();
                        throw null;
                    }
                }
            }
            if (i < iD) {
                arrayList2.add(obj2);
            }
        }
        return arrayList2;
    }
}

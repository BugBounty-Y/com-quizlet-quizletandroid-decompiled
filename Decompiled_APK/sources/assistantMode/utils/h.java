package assistantMode.utils;

import androidx.compose.animation.d0;
import assistantMode.enums.m;
import assistantMode.enums.q;
import assistantMode.enums.s;
import assistantMode.refactored.modelTypes.ParsedMultipleChoiceOption;
import assistantMode.refactored.modelTypes.TextValue;
import assistantMode.refactored.types.FillInTheBlankMultipleChoiceQuestionStudiableMetadata;
import assistantMode.refactored.types.FillInTheBlankQuestionStudiableMetadata;
import assistantMode.refactored.types.MLMCQDistractorStudiableMetadata;
import assistantMode.refactored.types.MultipleChoiceSelectAllThatApplyQuestionStudiableMetadata;
import assistantMode.refactored.types.ParsedMultipleChoiceQuestionStudiableMetadata;
import assistantMode.refactored.types.StudiableMetadataContent;
import assistantMode.types.C1454a;
import assistantMode.types.C1457d;
import assistantMode.types.G;
import assistantMode.types.QuestionStudiableMetadata;
import com.google.android.gms.internal.mlkit_vision_camera.k3;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import kotlin.collections.A;
import kotlin.collections.C;
import kotlin.collections.CollectionsKt;
import kotlin.collections.K;
import kotlin.collections.U;
import kotlin.collections.V;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class h {
    public final List a;
    public final ArrayList b;
    public final Long c;
    public final Map d;
    public final Object e;
    public final LinkedHashMap f;
    public final LinkedHashMap g;

    public h(ArrayList annotatedCards, ArrayList multipleChoiceQuestions, Map studiableMetadataByType) {
        Intrinsics.checkNotNullParameter(annotatedCards, "annotatedCards");
        Intrinsics.checkNotNullParameter(multipleChoiceQuestions, "multipleChoiceQuestions");
        Intrinsics.checkNotNullParameter(studiableMetadataByType, "studiableMetadataByType");
        this.d = V.c();
        this.e = V.c();
        this.d = studiableMetadataByType;
        this.e = b(annotatedCards, studiableMetadataByType);
        List listA = a(annotatedCards);
        this.a = listA;
        int iA = U.a(C.q(listA, 10));
        LinkedHashMap linkedHashMap = new LinkedHashMap(iA < 16 ? 16 : iA);
        for (Object obj : listA) {
            linkedHashMap.put(Long.valueOf(((C1454a) obj).a.a), obj);
        }
        this.f = linkedHashMap;
        List list = this.a;
        List list2 = assistantMode.a.b;
        int iA2 = U.a(C.q(list2, 10));
        LinkedHashMap linkedHashMap2 = new LinkedHashMap(iA2 >= 16 ? iA2 : 16);
        for (Object obj2 : list2) {
            m mVar = (m) obj2;
            LinkedHashMap linkedHashMap3 = new LinkedHashMap();
            for (Object obj3 : list) {
                String strD = ((C1454a) obj3).d(mVar);
                Object arrayList = linkedHashMap3.get(strD);
                if (arrayList == null) {
                    arrayList = new ArrayList();
                    linkedHashMap3.put(strD, arrayList);
                }
                ((List) arrayList).add(obj3);
            }
            LinkedHashMap linkedHashMap4 = new LinkedHashMap();
            for (Map.Entry entry : linkedHashMap3.entrySet()) {
                if (((String) entry.getKey()) != null) {
                    linkedHashMap4.put(entry.getKey(), entry.getValue());
                }
            }
            linkedHashMap2.put(obj2, linkedHashMap4);
        }
        this.g = linkedHashMap2;
        this.b = multipleChoiceQuestions;
        C1454a c1454a = (C1454a) CollectionsKt.firstOrNull(this.a);
        this.c = c1454a != null ? Long.valueOf(c1454a.a.o) : null;
        this.d = studiableMetadataByType;
        this.e = b(this.a, studiableMetadataByType);
        if (studiableMetadataByType.containsKey(s.f)) {
            this.a = a(this.a);
        }
    }

    public static LinkedHashMap b(List list, Map map) {
        LinkedHashMap linkedHashMapM = V.m(map);
        for (Map.Entry entry : map.entrySet()) {
            s sVar = (s) entry.getKey();
            StudiableMetadataContent studiableMetadataContent = (StudiableMetadataContent) entry.getValue();
            int iA = U.a(C.q(list, 10));
            if (iA < 16) {
                iA = 16;
            }
            LinkedHashMap linkedHashMap = new LinkedHashMap(iA);
            Iterator it2 = list.iterator();
            while (it2.hasNext()) {
                C1454a c1454a = (C1454a) it2.next();
                linkedHashMap.put(Long.valueOf(c1454a.a.a), c1454a.a.p);
            }
            List list2 = studiableMetadataContent.a;
            ArrayList studiableMetadata = new ArrayList();
            for (Object obj : list2) {
                assistantMode.refactored.types.f fVar = (assistantMode.refactored.types.f) obj;
                Long l = (Long) linkedHashMap.get(Long.valueOf(fVar.b()));
                if (l != null && l.longValue() <= fVar.a()) {
                    studiableMetadata.add(obj);
                }
            }
            Intrinsics.checkNotNullParameter(studiableMetadata, "studiableMetadata");
            q studiableMetadataStatus = studiableMetadataContent.b;
            Intrinsics.checkNotNullParameter(studiableMetadataStatus, "studiableMetadataStatus");
            linkedHashMapM.put(sVar, new StudiableMetadataContent(studiableMetadata, studiableMetadataStatus));
        }
        return linkedHashMapM;
    }

    /* JADX WARN: Type inference failed for: r2v0, types: [java.lang.Object, java.util.Map] */
    /* JADX WARN: Type inference failed for: r2v2, types: [java.lang.Object, java.util.Map] */
    public final List a(List list) {
        Integer numValueOf;
        Object next;
        String str;
        Object next2;
        String str2;
        ?? r2 = this.e;
        s sVar = s.f;
        if (r2.containsKey(sVar)) {
            StudiableMetadataContent studiableMetadataContent = (StudiableMetadataContent) this.e.get(sVar);
            List<ParsedMultipleChoiceQuestionStudiableMetadata> list2 = studiableMetadataContent != null ? studiableMetadataContent.a : null;
            Intrinsics.e(list2, "null cannot be cast to non-null type kotlin.collections.List<assistantMode.refactored.types.ParsedMultipleChoiceQuestionStudiableMetadata>");
            if (!list2.isEmpty()) {
                int iA = U.a(C.q(list2, 10));
                if (iA < 16) {
                    iA = 16;
                }
                LinkedHashMap linkedHashMap = new LinkedHashMap(iA);
                for (ParsedMultipleChoiceQuestionStudiableMetadata parsedMultipleChoiceQuestionStudiableMetadata : list2) {
                    Long lValueOf = Long.valueOf(parsedMultipleChoiceQuestionStudiableMetadata.a);
                    Iterator it2 = parsedMultipleChoiceQuestionStudiableMetadata.i.iterator();
                    while (true) {
                        if (!it2.hasNext()) {
                            next = null;
                            break;
                        }
                        next = it2.next();
                        if (next instanceof TextValue) {
                            break;
                        }
                    }
                    if (!(next instanceof TextValue)) {
                        next = null;
                    }
                    TextValue textValue = (TextValue) next;
                    if (textValue == null || (str = textValue.a) == null) {
                        str = "";
                    }
                    List<ParsedMultipleChoiceOption> list3 = parsedMultipleChoiceQuestionStudiableMetadata.j;
                    ArrayList arrayList = new ArrayList(C.q(list3, 10));
                    for (ParsedMultipleChoiceOption parsedMultipleChoiceOption : list3) {
                        Iterator it3 = parsedMultipleChoiceOption.a.iterator();
                        while (true) {
                            if (!it3.hasNext()) {
                                next2 = null;
                                break;
                            }
                            next2 = it3.next();
                            if (((assistantMode.refactored.modelTypes.c) next2) instanceof TextValue) {
                                break;
                            }
                        }
                        TextValue textValue2 = next2 instanceof TextValue ? (TextValue) next2 : null;
                        if (textValue2 == null || (str2 = textValue2.a) == null) {
                            str2 = "";
                        }
                        arrayList.add(new assistantMode.utils.parsing.b(str2, parsedMultipleChoiceOption.b));
                    }
                    linkedHashMap.put(lValueOf, new assistantMode.utils.parsing.a(str, arrayList, parsedMultipleChoiceQuestionStudiableMetadata.g, parsedMultipleChoiceQuestionStudiableMetadata.h));
                }
                LinkedHashMap linkedHashMap2 = new LinkedHashMap();
                for (Map.Entry entry : linkedHashMap.entrySet()) {
                    if (((assistantMode.utils.parsing.a) entry.getValue()).a.length() > 0) {
                        linkedHashMap2.put(entry.getKey(), entry.getValue());
                    }
                }
                ArrayList arrayList2 = new ArrayList(C.q(list, 10));
                Iterator it4 = list.iterator();
                while (it4.hasNext()) {
                    C1454a c1454a = (C1454a) it4.next();
                    assistantMode.utils.parsing.a aVar = (assistantMode.utils.parsing.a) linkedHashMap2.get(Long.valueOf(c1454a.a.a));
                    assistantMode.utils.parsing.a aVar2 = (assistantMode.utils.parsing.a) linkedHashMap2.get(Long.valueOf(c1454a.a.a));
                    if (aVar2 != null) {
                        Iterator it5 = aVar2.b.iterator();
                        int i = 0;
                        while (true) {
                            if (!it5.hasNext()) {
                                i = -1;
                                break;
                            }
                            if (((assistantMode.utils.parsing.b) it5.next()).b) {
                                break;
                            }
                            i++;
                        }
                        numValueOf = Integer.valueOf(i);
                    } else {
                        numValueOf = null;
                    }
                    G term = c1454a.a;
                    Intrinsics.checkNotNullParameter(term, "term");
                    k3 wordText = c1454a.b;
                    Intrinsics.checkNotNullParameter(wordText, "wordText");
                    k3 definitionText = c1454a.c;
                    Intrinsics.checkNotNullParameter(definitionText, "definitionText");
                    arrayList2.add(new C1454a(term, wordText, definitionText, c1454a.d, c1454a.e, c1454a.f, c1454a.g, c1454a.h, aVar, numValueOf, c1454a.k));
                }
                return arrayList2;
            }
        }
        return list;
    }

    public final List c(C1454a card, m cardSide) {
        Intrinsics.checkNotNullParameter(card, "card");
        Intrinsics.checkNotNullParameter(cardSide, "cardSide");
        Object obj = this.g.get(cardSide);
        if (obj == null) {
            throw new IllegalStateException(("Missing term side equivalence map for term side: " + cardSide).toString());
        }
        Map map = (Map) obj;
        if (card.d(cardSide) == null) {
            return A.b(card);
        }
        Object obj2 = map.get(card.d(cardSide));
        if (obj2 != null) {
            return (List) obj2;
        }
        throw new IllegalStateException(d0.n(card.a.a, "Missing term in list of terms equivalent to itself: ").toString());
    }

    public final ArrayList d(C1457d cardEdge) {
        ArrayList arrayList;
        Intrinsics.checkNotNullParameter(cardEdge, "cardEdge");
        List listI = i(s.h);
        if (listI != null) {
            ArrayList arrayList2 = new ArrayList();
            for (Object obj : listI) {
                if (obj instanceof FillInTheBlankMultipleChoiceQuestionStudiableMetadata) {
                    arrayList2.add(obj);
                }
            }
            arrayList = new ArrayList();
            Iterator it2 = arrayList2.iterator();
            while (it2.hasNext()) {
                Object next = it2.next();
                FillInTheBlankMultipleChoiceQuestionStudiableMetadata fillInTheBlankMultipleChoiceQuestionStudiableMetadata = (FillInTheBlankMultipleChoiceQuestionStudiableMetadata) next;
                if (fillInTheBlankMultipleChoiceQuestionStudiableMetadata.a == cardEdge.a.a.a && !fillInTheBlankMultipleChoiceQuestionStudiableMetadata.j.isEmpty() && fillInTheBlankMultipleChoiceQuestionStudiableMetadata.i == cardEdge.c) {
                    arrayList.add(next);
                }
            }
        } else {
            arrayList = null;
        }
        Intrinsics.e(arrayList, "null cannot be cast to non-null type kotlin.collections.List<assistantMode.refactored.types.FillInTheBlankMultipleChoiceQuestionStudiableMetadata>");
        return arrayList;
    }

    public final FillInTheBlankQuestionStudiableMetadata e(C1457d cardEdge) {
        Intrinsics.checkNotNullParameter(cardEdge, "cardEdge");
        List listI = i(s.c);
        Object obj = null;
        if (listI != null) {
            Iterator it2 = listI.iterator();
            while (true) {
                if (!it2.hasNext()) {
                    break;
                }
                Object next = it2.next();
                assistantMode.refactored.types.f fVar = (assistantMode.refactored.types.f) next;
                if (fVar.b() == cardEdge.a.a.a && ((FillInTheBlankQuestionStudiableMetadata) fVar).i == cardEdge.c) {
                    obj = next;
                    break;
                }
            }
            obj = (assistantMode.refactored.types.f) obj;
        }
        return (FillInTheBlankQuestionStudiableMetadata) obj;
    }

    public final MLMCQDistractorStudiableMetadata f(long j, m answerSide) {
        Intrinsics.checkNotNullParameter(answerSide, "answerSide");
        List listI = i(s.d);
        Object obj = null;
        if (listI != null) {
            Iterator it2 = listI.iterator();
            while (true) {
                if (!it2.hasNext()) {
                    break;
                }
                Object next = it2.next();
                assistantMode.refactored.types.f fVar = (assistantMode.refactored.types.f) next;
                if (!(fVar instanceof MLMCQDistractorStudiableMetadata)) {
                    throw new IllegalArgumentException(("Expected MLMCQDistractorStudiableMetadata, but got " + fVar).toString());
                }
                if (((MLMCQDistractorStudiableMetadata) fVar).a == j && ((MLMCQDistractorStudiableMetadata) fVar).g == answerSide) {
                    obj = next;
                    break;
                }
            }
            obj = (assistantMode.refactored.types.f) obj;
        }
        return (MLMCQDistractorStudiableMetadata) obj;
    }

    public final MultipleChoiceSelectAllThatApplyQuestionStudiableMetadata g(C1457d cardEdge) {
        Intrinsics.checkNotNullParameter(cardEdge, "cardEdge");
        List listI = i(s.g);
        ArrayList arrayList = new ArrayList();
        for (Object obj : listI) {
            if (obj instanceof MultipleChoiceSelectAllThatApplyQuestionStudiableMetadata) {
                arrayList.add(obj);
            }
        }
        ArrayList arrayList2 = new ArrayList();
        Iterator it2 = arrayList.iterator();
        while (it2.hasNext()) {
            Object next = it2.next();
            MultipleChoiceSelectAllThatApplyQuestionStudiableMetadata multipleChoiceSelectAllThatApplyQuestionStudiableMetadata = (MultipleChoiceSelectAllThatApplyQuestionStudiableMetadata) next;
            if (multipleChoiceSelectAllThatApplyQuestionStudiableMetadata.a == cardEdge.a.a.a && multipleChoiceSelectAllThatApplyQuestionStudiableMetadata.j == cardEdge.c) {
                arrayList2.add(next);
            }
        }
        return (MultipleChoiceSelectAllThatApplyQuestionStudiableMetadata) CollectionsKt.firstOrNull(arrayList2);
    }

    /* JADX WARN: Type inference failed for: r1v0, types: [java.lang.Object, java.util.Map] */
    /* JADX WARN: Type inference failed for: r1v12, types: [java.lang.Object, java.util.Map] */
    /* JADX WARN: Type inference failed for: r1v18, types: [java.lang.Object, java.util.Map] */
    /* JADX WARN: Type inference failed for: r1v6, types: [java.lang.Object, java.util.Map] */
    public final QuestionStudiableMetadata h(long j) {
        ?? r1 = this.e;
        LinkedHashMap linkedHashMap = new LinkedHashMap();
        for (Map.Entry entry : r1.entrySet()) {
            if (((StudiableMetadataContent) entry.getValue()).b == q.b || ((StudiableMetadataContent) entry.getValue()).b == q.e) {
                linkedHashMap.put(entry.getKey(), entry.getValue());
            }
        }
        ArrayList arrayList = new ArrayList(linkedHashMap.size());
        Iterator it2 = linkedHashMap.entrySet().iterator();
        while (it2.hasNext()) {
            arrayList.add((s) ((Map.Entry) it2.next()).getKey());
        }
        ?? r12 = this.e;
        LinkedHashMap linkedHashMap2 = new LinkedHashMap();
        for (Map.Entry entry2 : r12.entrySet()) {
            if (((StudiableMetadataContent) entry2.getValue()).b == q.c) {
                linkedHashMap2.put(entry2.getKey(), entry2.getValue());
            }
        }
        ArrayList arrayList2 = new ArrayList(linkedHashMap2.size());
        Iterator it3 = linkedHashMap2.entrySet().iterator();
        while (it3.hasNext()) {
            arrayList2.add((s) ((Map.Entry) it3.next()).getKey());
        }
        ?? r13 = this.e;
        LinkedHashMap linkedHashMap3 = new LinkedHashMap();
        for (Map.Entry entry3 : r13.entrySet()) {
            if (((StudiableMetadataContent) entry3.getValue()).b == q.d) {
                linkedHashMap3.put(entry3.getKey(), entry3.getValue());
            }
        }
        ArrayList arrayList3 = new ArrayList(linkedHashMap3.size());
        Iterator it4 = linkedHashMap3.entrySet().iterator();
        while (it4.hasNext()) {
            arrayList3.add((s) ((Map.Entry) it4.next()).getKey());
        }
        ?? r14 = this.e;
        LinkedHashMap linkedHashMap4 = new LinkedHashMap();
        for (Map.Entry entry4 : r14.entrySet()) {
            List list = ((StudiableMetadataContent) entry4.getValue()).a;
            if (list == null || !list.isEmpty()) {
                Iterator it5 = list.iterator();
                while (true) {
                    if (!it5.hasNext()) {
                        break;
                    }
                    if (((assistantMode.refactored.types.f) it5.next()).b() == j) {
                        linkedHashMap4.put(entry4.getKey(), entry4.getValue());
                        break;
                    }
                }
            }
        }
        ArrayList arrayList4 = new ArrayList(linkedHashMap4.size());
        Iterator it6 = linkedHashMap4.entrySet().iterator();
        while (it6.hasNext()) {
            arrayList4.add((s) ((Map.Entry) it6.next()).getKey());
        }
        List<C1454a> list2 = this.a;
        int iA = U.a(C.q(list2, 10));
        if (iA < 16) {
            iA = 16;
        }
        LinkedHashMap linkedHashMap5 = new LinkedHashMap(iA);
        for (C1454a c1454a : list2) {
            linkedHashMap5.put(Long.valueOf(c1454a.a.a), c1454a.a.p);
        }
        Map map = this.d;
        LinkedHashMap linkedHashMap6 = new LinkedHashMap();
        for (Map.Entry entry5 : map.entrySet()) {
            StudiableMetadataContent studiableMetadataContent = (StudiableMetadataContent) entry5.getValue();
            Long l = (Long) linkedHashMap5.get(Long.valueOf(j));
            List list3 = studiableMetadataContent.a;
            if (list3 == null || !list3.isEmpty()) {
                Iterator it7 = list3.iterator();
                while (true) {
                    if (it7.hasNext()) {
                        assistantMode.refactored.types.f fVar = (assistantMode.refactored.types.f) it7.next();
                        if (fVar.b() == j && l != null && l.longValue() > fVar.a()) {
                            linkedHashMap6.put(entry5.getKey(), entry5.getValue());
                            break;
                        }
                    }
                }
            }
        }
        ArrayList arrayList5 = new ArrayList(linkedHashMap6.size());
        Iterator it8 = linkedHashMap6.entrySet().iterator();
        while (it8.hasNext()) {
            arrayList5.add((s) ((Map.Entry) it8.next()).getKey());
        }
        return new QuestionStudiableMetadata(arrayList, arrayList2, arrayList3, arrayList4, arrayList5);
    }

    /* JADX WARN: Type inference failed for: r0v0, types: [java.lang.Object, java.util.Map] */
    public final List i(s sVar) {
        List list;
        StudiableMetadataContent studiableMetadataContent = (StudiableMetadataContent) this.e.get(sVar);
        return (studiableMetadataContent == null || (list = studiableMetadataContent.a) == null) ? K.a : list;
    }

    /* JADX WARN: Type inference failed for: r1v0, types: [java.lang.Object, java.util.Map] */
    public final LinkedHashMap j() {
        LinkedHashMap linkedHashMap = new LinkedHashMap();
        Set setEntrySet = this.e.entrySet();
        ArrayList arrayList = new ArrayList();
        for (Object obj : setEntrySet) {
            if (!((StudiableMetadataContent) ((Map.Entry) obj).getValue()).a.isEmpty()) {
                arrayList.add(obj);
            }
        }
        Iterator it2 = arrayList.iterator();
        while (it2.hasNext()) {
            Map.Entry entry = (Map.Entry) it2.next();
            linkedHashMap.put(entry.getKey(), ((assistantMode.refactored.types.f) CollectionsKt.L(((StudiableMetadataContent) entry.getValue()).a)).c());
        }
        if (linkedHashMap.isEmpty()) {
            return null;
        }
        return linkedHashMap;
    }

    public final boolean k(m cardSide) {
        int i;
        Intrinsics.checkNotNullParameter(cardSide, "cardSide");
        Intrinsics.checkNotNullParameter(cardSide, "cardSide");
        Object obj = this.g.get(cardSide);
        if (obj == null) {
            throw new IllegalStateException(("Missing term side equivalence map for card side: " + cardSide).toString());
        }
        Map map = (Map) obj;
        if (map.isEmpty()) {
            i = 0;
        } else {
            Iterator it2 = map.entrySet().iterator();
            i = 0;
            while (it2.hasNext()) {
                if (((String) ((Map.Entry) it2.next()).getKey()) != null) {
                    i++;
                }
            }
        }
        return i > 1;
    }
}

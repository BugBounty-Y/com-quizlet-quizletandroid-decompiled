package assistantMode.questions.generators;

import assistantMode.enums.m;
import assistantMode.grading.MatchingGameAnswerPair;
import assistantMode.grading.p;
import assistantMode.refactored.modelTypes.TextValue;
import assistantMode.refactored.types.FITBTextSegment;
import assistantMode.refactored.types.FITBWrittenBlankSegment;
import assistantMode.refactored.types.FillInTheBlankKeyphraseLocation;
import assistantMode.refactored.types.FillInTheBlankQuestion;
import assistantMode.refactored.types.FillInTheBlankQuestionStudiableMetadata;
import assistantMode.refactored.types.MixedOptionMatchingQuestion;
import assistantMode.types.C1454a;
import assistantMode.types.C1457d;
import assistantMode.types.QuestionElement;
import assistantMode.types.QuestionMetadata;
import assistantMode.types.n;
import assistantMode.types.unions.TextAttribute;
import com.google.android.gms.internal.mlkit_vision_camera.N2;
import com.google.android.gms.internal.mlkit_vision_camera.Q2;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import kotlin.Pair;
import kotlin.Unit;
import kotlin.collections.A;
import kotlin.collections.B;
import kotlin.collections.C;
import kotlin.collections.C4933y;
import kotlin.collections.CollectionsKt;
import kotlin.collections.K;
import kotlin.collections.V;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class h extends Q2 {
    public final /* synthetic */ int a = 0;
    public final ArrayList b;
    public final Object c;
    public final Object d;
    public final Object e;
    public final assistantMode.refactored.types.d f;

    public h(n questionConfig) {
        Intrinsics.checkNotNullParameter(questionConfig, "questionConfig");
        assistantMode.enums.k questionType = assistantMode.enums.k.k;
        Intrinsics.checkNotNullParameter(questionType, "questionType");
        this.c = questionConfig;
        ArrayList arrayListD = N2.d(questionConfig.b, CollectionsKt.w0(questionConfig.a));
        List list = questionConfig.a;
        ArrayList arrayListD2 = N2.d(questionConfig.c, CollectionsKt.w0(list));
        List listC = A.c(kotlin.ranges.l.h(0, list.size() * 2));
        this.d = listC;
        this.b = CollectionsKt.c0(arrayListD, arrayListD2);
        ArrayList arrayList = new ArrayList(C.q(listC, 10));
        Iterator it2 = ((ArrayList) listC).iterator();
        while (it2.hasNext()) {
            arrayList.add((QuestionElement) this.b.get(((Number) it2.next()).intValue()));
        }
        this.e = arrayList;
        n nVar = (n) this.c;
        this.f = new MixedOptionMatchingQuestion(arrayList, new QuestionMetadata(null, nVar.b, nVar.c, null, null, null, 248));
    }

    @Override // com.google.android.gms.internal.mlkit_vision_camera.Q2
    public int b() {
        switch (this.a) {
            case 1:
                return ((n) this.c).a.size();
            default:
                return super.b();
        }
    }

    @Override // com.google.android.gms.internal.mlkit_vision_camera.Q2
    public final assistantMode.grading.d c() {
        ArrayList arrayList;
        Iterator it2;
        n nVar;
        List<C1454a> list;
        switch (this.a) {
            case 0:
                LinkedHashMap linkedHashMap = (LinkedHashMap) this.e;
                Object obj = linkedHashMap.get(0L);
                if (obj != null) {
                    TextValue textValue = (TextValue) obj;
                    return new p(textValue.a, new QuestionElement(A.b(new TextAttribute(textValue.a, textValue.b, null))), K.a, null, null, textValue.b);
                }
                throw new IllegalStateException(("Cannot get expected answer for Fill In The Blank grader. Segments: " + this.b + "; expected answers map: " + linkedHashMap).toString());
            default:
                LinkedHashSet linkedHashSet = new LinkedHashSet();
                ArrayList arrayList2 = (ArrayList) this.e;
                Iterator it3 = arrayList2.iterator();
                int i = 0;
                while (it3.hasNext()) {
                    Object next = it3.next();
                    int i2 = i + 1;
                    if (i < 0) {
                        B.p();
                        throw null;
                    }
                    QuestionElement questionElement = (QuestionElement) next;
                    Iterator it4 = arrayList2.iterator();
                    int i3 = 0;
                    while (it4.hasNext()) {
                        Object next2 = it4.next();
                        int i4 = i3 + 1;
                        if (i3 < 0) {
                            B.p();
                            throw null;
                        }
                        QuestionElement questionElement2 = (QuestionElement) next2;
                        if (i == i3 || ((list = (nVar = (n) this.c).a) != null && list.isEmpty())) {
                            arrayList = arrayList2;
                            it2 = it3;
                        } else {
                            for (C1454a c1454a : list) {
                                QuestionElement questionElementC = N2.c(c1454a, nVar.b);
                                arrayList = arrayList2;
                                QuestionElement questionElementC2 = N2.c(c1454a, nVar.c);
                                QuestionElement[] elements = {questionElement, questionElement2};
                                it2 = it3;
                                Intrinsics.checkNotNullParameter(elements, "elements");
                                Set setT = C4933y.T(elements);
                                QuestionElement[] elements2 = {questionElementC, questionElementC2};
                                Intrinsics.checkNotNullParameter(elements2, "elements");
                                if (Intrinsics.b(setT, C4933y.T(elements2))) {
                                    linkedHashSet.add(new MatchingGameAnswerPair(i, i3));
                                } else {
                                    arrayList2 = arrayList;
                                    it3 = it2;
                                }
                            }
                            arrayList = arrayList2;
                            it2 = it3;
                        }
                        i3 = i4;
                        arrayList2 = arrayList;
                        it3 = it2;
                    }
                    i = i2;
                }
                List list2 = (List) this.d;
                ArrayList arrayList3 = new ArrayList(C.q(list2, 10));
                int i5 = 0;
                for (Object obj2 : list2) {
                    int i6 = i5 + 1;
                    if (i5 < 0) {
                        B.p();
                        throw null;
                    }
                    arrayList3.add(new Pair(Integer.valueOf(i5), this.b.get(((Number) obj2).intValue())));
                    i5 = i6;
                }
                return new assistantMode.grading.c(linkedHashSet, V.k(arrayList3));
        }
    }

    @Override // com.google.android.gms.internal.mlkit_vision_camera.Q2
    public final assistantMode.refactored.types.d d() {
        switch (this.a) {
            case 0:
                return (FillInTheBlankQuestion) this.f;
            default:
                return (MixedOptionMatchingQuestion) this.f;
        }
    }

    @Override // com.google.android.gms.internal.mlkit_vision_camera.Q2
    public final List e() {
        switch (this.a) {
            case 0:
                return A.b(Long.valueOf(((C1457d) this.c).a.a.a));
            default:
                List list = (List) this.d;
                ArrayList arrayList = new ArrayList(C.q(list, 10));
                Iterator it2 = list.iterator();
                while (it2.hasNext()) {
                    int iIntValue = ((Number) it2.next()).intValue();
                    n nVar = (n) this.c;
                    arrayList.add(Long.valueOf(((C1454a) nVar.a.get(iIntValue % nVar.a.size())).a.a));
                }
                return arrayList;
        }
    }

    public h(assistantMode.types.j questionConfig, assistantMode.utils.h studyableMaterialDataSource) {
        Iterator it2;
        Intrinsics.checkNotNullParameter(questionConfig, "questionConfig");
        Intrinsics.checkNotNullParameter(studyableMaterialDataSource, "studyableMaterialDataSource");
        assistantMode.enums.k questionType = assistantMode.enums.k.l;
        Intrinsics.checkNotNullParameter(questionType, "questionType");
        C1457d c1457d = questionConfig.b;
        this.c = c1457d;
        FillInTheBlankQuestionStudiableMetadata fillInTheBlankQuestionStudiableMetadata = questionConfig.a;
        this.d = fillInTheBlankQuestionStudiableMetadata;
        m mVar = m.d;
        m mVar2 = c1457d.c;
        if (mVar2 != mVar) {
            List list = fillInTheBlankQuestionStudiableMetadata.h;
            if (list.size() == 1) {
                assistantMode.refactored.modelTypes.c cVar = fillInTheBlankQuestionStudiableMetadata.g;
                boolean z = cVar instanceof TextValue;
                C1454a c1454a = c1457d.a;
                if (z) {
                    List listN0 = CollectionsKt.n0(list, new androidx.constraintlayout.core.e(8));
                    ArrayList segments = new ArrayList();
                    LinkedHashMap expectedAnswersMap = V.m(V.c());
                    String strE = c1454a.i(mVar2).e();
                    String strC = c1454a.i(mVar2).c();
                    ArrayList arrayList = new ArrayList(C.q(listN0, 10));
                    Iterator it3 = listN0.iterator();
                    int i = 0;
                    int i2 = 0;
                    while (it3.hasNext()) {
                        Object next = it3.next();
                        int i3 = i2 + 1;
                        if (i2 < 0) {
                            B.p();
                            throw null;
                        }
                        FillInTheBlankKeyphraseLocation fillInTheBlankKeyphraseLocation = (FillInTheBlankKeyphraseLocation) next;
                        int i4 = fillInTheBlankKeyphraseLocation.a;
                        if (i4 != 0) {
                            String strSubstring = strE.substring(i, i4);
                            Intrinsics.checkNotNullExpressionValue(strSubstring, "substring(...)");
                            it2 = it3;
                            segments.add(new FITBTextSegment(new TextAttribute(strSubstring, strC, null)));
                        } else {
                            it2 = it3;
                        }
                        i = i4 + fillInTheBlankKeyphraseLocation.b;
                        String strSubstring2 = strE.substring(i4, i);
                        Intrinsics.checkNotNullExpressionValue(strSubstring2, "substring(...)");
                        long j = i2;
                        segments.add(new FITBWrittenBlankSegment(strC, j));
                        expectedAnswersMap.put(Long.valueOf(j), new TextValue(strSubstring2, strC, null, null, null));
                        arrayList.add(Unit.a);
                        it3 = it2;
                        i2 = i3;
                    }
                    if (i < strE.length()) {
                        String strSubstring3 = strE.substring(i);
                        Intrinsics.checkNotNullExpressionValue(strSubstring3, "substring(...)");
                        segments.add(new FITBTextSegment(new TextAttribute(strSubstring3, strC, null)));
                    }
                    Intrinsics.checkNotNullParameter(segments, "segments");
                    Intrinsics.checkNotNullParameter(expectedAnswersMap, "expectedAnswersMap");
                    this.b = segments;
                    this.e = expectedAnswersMap;
                    C1457d c1457d2 = (C1457d) this.c;
                    QuestionElement questionElementC = N2.c(c1457d2.a, c1457d2.b);
                    Long lValueOf = Long.valueOf(((C1457d) this.c).a.a.a);
                    C1457d c1457d3 = (C1457d) this.c;
                    this.f = new FillInTheBlankQuestion(questionElementC, segments, new QuestionMetadata(lValueOf, c1457d3.b, c1457d3.c, null, studyableMaterialDataSource.h(c1457d3.a.a.a), studyableMaterialDataSource.j(), 136), ((FillInTheBlankQuestionStudiableMetadata) this.d).e);
                    return;
                }
                throw new IllegalArgumentException(("FillInTheBlank only supports text keyphrases. Received: " + cVar + " for " + c1454a.a.a).toString());
            }
            throw new IllegalArgumentException("FillInTheBlank only supports 1 answer per question");
        }
        throw new IllegalArgumentException("FillInTheBlank only supports WORD and DEFINITION answer sides");
    }
}

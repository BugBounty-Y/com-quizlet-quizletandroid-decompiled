package assistantMode.questions.generators;

import assistantMode.grading.o;
import assistantMode.refactored.modelTypes.CardSideDistractor;
import assistantMode.refactored.modelTypes.TextValue;
import assistantMode.refactored.types.FITBMCQBlankSegment;
import assistantMode.refactored.types.FITBTextSegment;
import assistantMode.refactored.types.FillInTheBlankKeyphraseLocation;
import assistantMode.refactored.types.FillInTheBlankMultipleChoiceQuestion;
import assistantMode.refactored.types.FillInTheBlankMultipleChoiceQuestionStudiableMetadata;
import assistantMode.refactored.types.TrueFalseQuestion;
import assistantMode.types.B;
import assistantMode.types.C1454a;
import assistantMode.types.C1457d;
import assistantMode.types.QuestionElement;
import assistantMode.types.QuestionMetadata;
import assistantMode.types.unions.TextAttribute;
import com.comscore.streaming.AdvertisementType;
import com.google.android.gms.internal.mlkit_vision_camera.N2;
import com.google.android.gms.internal.mlkit_vision_camera.Q2;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import kotlin.Unit;
import kotlin.collections.A;
import kotlin.collections.C;
import kotlin.collections.CollectionsKt;
import kotlin.collections.V;
import kotlin.jvm.internal.Intrinsics;
import kotlin.m;
import kotlin.text.Regex;
import kotlin.v;

/* loaded from: classes.dex */
public final class f extends Q2 {
    public final /* synthetic */ int a = 1;
    public final boolean b;
    public final Object c;
    public final Object d;
    public final Object e;
    public final assistantMode.refactored.types.d f;

    public f(B questionConfig, assistantMode.utils.h studyableMaterialDataSource) {
        Intrinsics.checkNotNullParameter(questionConfig, "questionConfig");
        Intrinsics.checkNotNullParameter(studyableMaterialDataSource, "studyableMaterialDataSource");
        assistantMode.enums.k questionType = assistantMode.enums.k.e;
        Intrinsics.checkNotNullParameter(questionType, "questionType");
        this.c = questionConfig;
        kotlin.k kVarA = kotlin.l.a(m.a, new o(0, 4));
        this.d = kVarA;
        C1454a c1454a = (C1454a) questionConfig.a().get(0);
        this.e = c1454a;
        C1457d c1457d = questionConfig.a;
        QuestionElement questionElementC = N2.c(c1454a, c1457d.b);
        boolean z = ((kotlin.random.e) kVarA.getValue()).b() >= 0.5d;
        this.b = z;
        C1454a c1454a2 = (C1454a) questionConfig.a().get(0);
        if (!z) {
            c1454a2 = (C1454a) CollectionsKt.L(assistantMode.utils.g.c(c1454a2, c1457d.b, c1457d.c, studyableMaterialDataSource, 1, true, (kotlin.random.e) kVarA.getValue()));
        }
        this.f = new TrueFalseQuestion(questionElementC, N2.c(c1454a2, c1457d.c), new QuestionMetadata(Long.valueOf(c1454a.a.a), c1457d.b, c1457d.c, null, null, null, AdvertisementType.BRANDED_ON_DEMAND_MID_ROLL));
    }

    @Override // com.google.android.gms.internal.mlkit_vision_camera.Q2
    public int b() {
        switch (this.a) {
            case 0:
                return e().size();
            default:
                return super.b();
        }
    }

    @Override // com.google.android.gms.internal.mlkit_vision_camera.Q2
    public final assistantMode.grading.d c() {
        switch (this.a) {
            case 0:
                return new assistantMode.grading.a((LinkedHashMap) this.e);
            default:
                return new assistantMode.grading.m(this.b, N2.c((C1454a) this.e, ((B) this.c).a.c));
        }
    }

    @Override // com.google.android.gms.internal.mlkit_vision_camera.Q2
    public final assistantMode.refactored.types.d d() {
        switch (this.a) {
            case 0:
                return (FillInTheBlankMultipleChoiceQuestion) this.f;
            default:
                return (TrueFalseQuestion) this.f;
        }
    }

    @Override // com.google.android.gms.internal.mlkit_vision_camera.Q2
    public final List e() {
        switch (this.a) {
            case 0:
                return A.b(Long.valueOf(((C1457d) this.c).a.a.a));
            default:
                List listA = ((B) this.c).a();
                ArrayList arrayList = new ArrayList(C.q(listA, 10));
                Iterator it2 = listA.iterator();
                while (it2.hasNext()) {
                    arrayList.add(Long.valueOf(((C1454a) it2.next()).a.a));
                }
                return arrayList;
        }
    }

    /* JADX WARN: Type inference failed for: r15v2, types: [java.lang.Object, java.util.Map] */
    public f(assistantMode.types.i questionConfig, assistantMode.utils.h studyableMaterialDataSource) {
        Iterator it2;
        assistantMode.refactored.modelTypes.c cVar;
        int i;
        int i2;
        String str;
        int i3 = 0;
        Intrinsics.checkNotNullParameter(questionConfig, "questionConfig");
        Intrinsics.checkNotNullParameter(studyableMaterialDataSource, "studyableMaterialDataSource");
        assistantMode.enums.k questionType = assistantMode.enums.k.n;
        Intrinsics.checkNotNullParameter(questionType, "questionType");
        C1457d c1457d = questionConfig.b;
        this.c = c1457d;
        ArrayList<FillInTheBlankMultipleChoiceQuestionStudiableMetadata> arrayList = questionConfig.a;
        C1454a c1454a = c1457d.a;
        this.d = N2.c(c1454a, c1457d.b);
        this.b = arrayList.size() > 1;
        ArrayList arrayList2 = new ArrayList(C.q(arrayList, 10));
        for (FillInTheBlankMultipleChoiceQuestionStudiableMetadata fillInTheBlankMultipleChoiceQuestionStudiableMetadata : arrayList) {
            arrayList2.add(new v(fillInTheBlankMultipleChoiceQuestionStudiableMetadata.h, fillInTheBlankMultipleChoiceQuestionStudiableMetadata.g, fillInTheBlankMultipleChoiceQuestionStudiableMetadata.j));
        }
        List listN0 = CollectionsKt.n0(arrayList2, new androidx.constraintlayout.core.e(7));
        ArrayList segments = new ArrayList();
        LinkedHashMap expectedAnswersMap = V.m(V.c());
        assistantMode.enums.m mVar = c1457d.c;
        String strE = c1454a.i(mVar).e();
        String strC = c1454a.i(mVar).c();
        ArrayList arrayList3 = new ArrayList(C.q(listN0, 10));
        Iterator it3 = listN0.iterator();
        int i4 = 0;
        while (it3.hasNext()) {
            Object next = it3.next();
            int i5 = i4 + 1;
            if (i4 < 0) {
                kotlin.collections.B.p();
                throw null;
            }
            v vVar = (v) next;
            FillInTheBlankKeyphraseLocation fillInTheBlankKeyphraseLocation = (FillInTheBlankKeyphraseLocation) vVar.a;
            assistantMode.refactored.modelTypes.c cVar2 = (assistantMode.refactored.modelTypes.c) vVar.b;
            List list = (List) vVar.c;
            int i6 = fillInTheBlankKeyphraseLocation.a;
            if (i6 != 0) {
                String preBlankText = strE.substring(i3, i6);
                Intrinsics.checkNotNullExpressionValue(preBlankText, "substring(...)");
                if (cVar2 instanceof TextValue) {
                    it2 = it3;
                    if (Intrinsics.b(((TextValue) cVar2).b, "en")) {
                        Regex regex = g.a;
                        Intrinsics.checkNotNullParameter(preBlankText, "preBlankText");
                        Regex regex2 = g.a;
                        if (regex2.a(preBlankText)) {
                            kotlin.text.m mVarB = regex2.b(preBlankText);
                            String value = mVarB != null ? mVarB.getValue() : null;
                            if (value != null) {
                                cVar = cVar2;
                                Regex regex3 = g.b;
                                kotlin.text.m mVarB2 = regex3.b(value);
                                if (mVarB2 != null) {
                                    String value2 = mVarB2.getValue();
                                    i = i6;
                                    str = value2;
                                } else {
                                    i = i6;
                                    str = null;
                                }
                                i2 = i5;
                                String str2 = (String) g.c.get(str);
                                if (str2 != null) {
                                    preBlankText = regex2.replace(preBlankText, regex3.replace(value, str2));
                                }
                            }
                            segments.add(new FITBTextSegment(new TextAttribute(preBlankText, strC, null)));
                        }
                    }
                } else {
                    it2 = it3;
                }
                cVar = cVar2;
                i = i6;
                i2 = i5;
                segments.add(new FITBTextSegment(new TextAttribute(preBlankText, strC, null)));
            } else {
                it2 = it3;
                cVar = cVar2;
                i = i6;
                i2 = i5;
            }
            ArrayList arrayList4 = new ArrayList(C.q(list, 10));
            Iterator it4 = list.iterator();
            while (it4.hasNext()) {
                arrayList4.add(new QuestionElement(assistantMode.utils.g.o(((CardSideDistractor) it4.next()).a)));
            }
            ArrayList arrayListY0 = CollectionsKt.y0(arrayList4);
            QuestionElement questionElement = new QuestionElement(assistantMode.utils.g.o(A.b(cVar)));
            arrayListY0.add(questionElement);
            Collections.shuffle(arrayListY0);
            int iIndexOf = arrayListY0.indexOf(questionElement);
            segments.add(new FITBMCQBlankSegment(strC, i4, arrayListY0));
            expectedAnswersMap.put(Integer.valueOf(i4), Integer.valueOf(iIndexOf));
            int i7 = i + fillInTheBlankKeyphraseLocation.b;
            arrayList3.add(Unit.a);
            i4 = i2;
            i3 = i7;
            it3 = it2;
        }
        if (i3 < strE.length()) {
            String strSubstring = strE.substring(i3);
            Intrinsics.checkNotNullExpressionValue(strSubstring, "substring(...)");
            segments.add(new FITBTextSegment(new TextAttribute(strSubstring, strC, null)));
        }
        Intrinsics.checkNotNullParameter(segments, "segments");
        Intrinsics.checkNotNullParameter(expectedAnswersMap, "expectedAnswersMap");
        this.e = expectedAnswersMap;
        QuestionElement questionElement2 = (QuestionElement) this.d;
        boolean z = this.b;
        Long lValueOf = Long.valueOf(((C1457d) this.c).a.a.a);
        C1457d c1457d2 = (C1457d) this.c;
        this.f = new FillInTheBlankMultipleChoiceQuestion(questionElement2, segments, z, new QuestionMetadata(lValueOf, c1457d2.b, c1457d2.c, null, studyableMaterialDataSource.h(c1457d2.a.a.a), studyableMaterialDataSource.j(), 152));
    }
}

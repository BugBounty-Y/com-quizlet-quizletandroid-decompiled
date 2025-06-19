package assistantMode.utils;

import assistantMode.enums.m;
import assistantMode.refactored.modelTypes.AudioValue;
import assistantMode.refactored.modelTypes.DiagramShapeValue;
import assistantMode.refactored.modelTypes.ImageValue;
import assistantMode.refactored.modelTypes.TextValue;
import assistantMode.refactored.modelTypes.VideoValue;
import assistantMode.types.C1454a;
import assistantMode.types.OptionIndexAnswer;
import assistantMode.types.OptionIndicesAnswer;
import assistantMode.types.unions.AudioAttribute;
import assistantMode.types.unions.ImageAttribute;
import assistantMode.types.unions.TextAttribute;
import assistantMode.types.unions.VideoAttribute;
import com.google.android.gms.internal.mlkit_vision_camera.j3;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Pair;
import kotlin.collections.A;
import kotlin.collections.B;
import kotlin.collections.C;
import kotlin.collections.C4933y;
import kotlin.collections.CollectionsKt;
import kotlin.collections.G;
import kotlin.collections.K;
import kotlin.collections.U;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.I;
import kotlin.text.StringsKt;

/* loaded from: classes.dex */
public abstract class g {
    public static final androidx.constraintlayout.core.e a = new androidx.constraintlayout.core.e(19);

    public static final boolean a(C1454a term1, C1454a term2, m cardSide) {
        Intrinsics.checkNotNullParameter(term1, "term1");
        Intrinsics.checkNotNullParameter(term2, "term2");
        Intrinsics.checkNotNullParameter(cardSide, "cardSide");
        return Intrinsics.b(term1.d(cardSide), term2.d(cardSide));
    }

    public static final boolean b(ArrayList arrayList, C1454a c1454a, m mVar) {
        if (arrayList.isEmpty()) {
            return false;
        }
        Iterator it2 = arrayList.iterator();
        while (it2.hasNext()) {
            if (a((C1454a) it2.next(), c1454a, mVar)) {
                return true;
            }
        }
        return false;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r7v12, types: [java.util.ArrayList] */
    /* JADX WARN: Type inference failed for: r7v3, types: [kotlin.collections.K] */
    /* JADX WARN: Type inference failed for: r7v4, types: [java.lang.Iterable] */
    public static final List c(C1454a questionCard, m promptSide, m answerSide, h studyableMaterialDataSource, int i, boolean z, kotlin.random.e random) {
        ?? arrayList;
        double d;
        Intrinsics.checkNotNullParameter(questionCard, "questionCard");
        Intrinsics.checkNotNullParameter(promptSide, "promptSide");
        Intrinsics.checkNotNullParameter(answerSide, "answerSide");
        Intrinsics.checkNotNullParameter(studyableMaterialDataSource, "studyableMaterialDataSource");
        Intrinsics.checkNotNullParameter(random, "random");
        if (i <= 0) {
            return K.a;
        }
        List listN = B.n(studyableMaterialDataSource.a, random);
        List<C1454a> listW0 = CollectionsKt.w0(CollectionsKt.p0(listN, 30));
        ArrayList arrayListD0 = CollectionsKt.d0(listW0, questionCard);
        List listJ = B.j(promptSide, answerSide);
        int i2 = 10;
        int iA = U.a(C.q(listJ, 10));
        int i3 = 16;
        if (iA < 16) {
            iA = 16;
        }
        LinkedHashMap linkedHashMap = new LinkedHashMap(iA);
        Iterator it2 = listJ.iterator();
        while (it2.hasNext()) {
            Object next = it2.next();
            m mVar = (m) next;
            int iA2 = U.a(C.q(arrayListD0, i2));
            if (iA2 < i3) {
                iA2 = i3;
            }
            LinkedHashMap linkedHashMap2 = new LinkedHashMap(iA2);
            Iterator it3 = arrayListD0.iterator();
            while (it3.hasNext()) {
                C1454a c1454a = (C1454a) it3.next();
                Object obj = next;
                linkedHashMap2.put(Long.valueOf(c1454a.a.a), !f(mVar) ? null : h(c1454a.i(mVar).e()));
                next = obj;
            }
            linkedHashMap.put(next, linkedHashMap2);
            i2 = 10;
            i3 = 16;
        }
        int i4 = 3;
        int i5 = 2;
        int i6 = 1;
        ArrayList arrayList2 = new ArrayList(C.q(listW0, 10));
        for (C1454a c1454a2 : listW0) {
            double dJ = j(questionCard, c1454a2, promptSide, linkedHashMap);
            double dJ2 = j(questionCard, c1454a2, answerSide, linkedHashMap);
            double dK = k(questionCard, c1454a2, promptSide, linkedHashMap);
            double dK2 = k(questionCard, c1454a2, answerSide, linkedHashMap);
            double d2 = 0.0d;
            if (f(promptSide) && questionCard.i(promptSide).d() != c1454a2.i(promptSide).d()) {
                d = 0.0d;
                d2 = 1.0d;
            } else {
                d = 0.0d;
            }
            arrayList2.add(new d(dJ2, dJ, dK, dK2, d2, (f(answerSide) && questionCard.i(answerSide).d() != c1454a2.i(answerSide).d()) ? 1.0d : d, m(questionCard, c1454a2, promptSide), m(questionCard, c1454a2, answerSide), (questionCard.h(answerSide) != null) == (c1454a2.h(answerSide) != null) ? d : 1.0d, c1454a2.i(m.b).e()));
        }
        ArrayList arrayList3 = new ArrayList(C.q(arrayList2, 10));
        Iterator it4 = arrayList2.iterator();
        while (it4.hasNext()) {
            arrayList3.add(Double.valueOf(((d) it4.next()).b));
        }
        List listG = g(arrayList3);
        ArrayList arrayList4 = new ArrayList(C.q(arrayList2, 10));
        Iterator it5 = arrayList2.iterator();
        while (it5.hasNext()) {
            arrayList4.add(Double.valueOf(((d) it5.next()).a));
        }
        List listG2 = g(arrayList4);
        ArrayList arrayList5 = new ArrayList(C.q(arrayList2, 10));
        Iterator it6 = arrayList2.iterator();
        while (it6.hasNext()) {
            arrayList5.add(Double.valueOf(((d) it6.next()).c));
        }
        List listG3 = g(arrayList5);
        ArrayList arrayList6 = new ArrayList(C.q(arrayList2, 10));
        Iterator it7 = arrayList2.iterator();
        while (it7.hasNext()) {
            arrayList6.add(Double.valueOf(((d) it7.next()).d));
        }
        List[] listArr = (List[]) Arrays.copyOf(new List[]{listG, listG2, listG3, g(arrayList6)}, 4);
        ArrayList arrayList7 = new ArrayList(listArr.length);
        for (List list : listArr) {
            arrayList7.add(Integer.valueOf(list.size()));
        }
        Integer num = (Integer) CollectionsKt.Y(arrayList7);
        if (num != null) {
            int iIntValue = num.intValue();
            arrayList = new ArrayList(iIntValue);
            ArrayList arrayList8 = new ArrayList(listArr.length);
            for (List list2 : listArr) {
                arrayList8.add(list2.iterator());
            }
            for (int i7 = 0; i7 < iIntValue; i7++) {
                ArrayList arrayList9 = new ArrayList(C.q(arrayList8, 10));
                Iterator it8 = arrayList8.iterator();
                while (it8.hasNext()) {
                    arrayList9.add(((Iterator) it8.next()).next());
                }
                arrayList.add(arrayList9);
            }
        } else {
            arrayList = K.a;
        }
        Iterator it9 = arrayList.iterator();
        ArrayList arrayList10 = new ArrayList(Math.min(C.q(arrayList2, 10), C.q(arrayList, 10)));
        for (Iterator it10 = arrayList2.iterator(); it10.hasNext() && it9.hasNext(); it10 = it10) {
            Object next2 = it10.next();
            List list3 = (List) it9.next();
            d dVar = (d) next2;
            double d3 = i5;
            Iterator it11 = it9;
            int i8 = i6;
            int i9 = i4;
            arrayList10.add(Double.valueOf((((Number) list3.get(i9)).doubleValue() * 0.2d) + (((Number) list3.get(2)).doubleValue() * 0.15d) + (((Number) list3.get(i8)).doubleValue() * 0.3d) + (((Number) list3.get(0)).doubleValue() * 0.25d) + (dVar.h * d3) + (dVar.f * d3) + dVar.e + dVar.g + dVar.i));
            i5 = 2;
            i4 = i9;
            it9 = it11;
            i6 = i8;
        }
        List listN0 = CollectionsKt.n0(CollectionsKt.C0(listW0, arrayList10), new androidx.constraintlayout.core.e(18));
        ArrayList arrayList11 = new ArrayList(C.q(listN0, 10));
        Iterator it12 = listN0.iterator();
        while (it12.hasNext()) {
            arrayList11.add((C1454a) ((Pair) it12.next()).a);
        }
        ArrayList arrayListL = l(arrayList11, i, z, false, questionCard, promptSide, answerSide, false);
        return arrayListL.size() < i ? l(CollectionsKt.c0(arrayListL, CollectionsKt.w0(listN)), i, z, false, questionCard, promptSide, answerSide, false) : arrayListL;
    }

    public static final String d(C1454a c1454a, m mVar, LinkedHashMap linkedHashMap) {
        Map map = (Map) linkedHashMap.get(mVar);
        if (map != null) {
            return (String) map.get(Long.valueOf(c1454a.a.a));
        }
        throw new Error("Card side " + mVar + " missing in normalizedTextMap");
    }

    /* JADX WARN: Removed duplicated region for block: B:20:0x0039  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final boolean e(assistantMode.types.C1454a r6, assistantMode.types.C1454a r7, assistantMode.enums.m r8, assistantMode.enums.m r9, boolean r10, boolean r11, boolean r12) {
        /*
            assistantMode.types.G r0 = r7.a
            long r1 = r0.a
            assistantMode.types.G r3 = r6.a
            long r4 = r3.a
            int r1 = (r1 > r4 ? 1 : (r1 == r4 ? 0 : -1))
            r2 = 0
            if (r1 != 0) goto Le
            goto L53
        Le:
            long r3 = r3.o
            long r0 = r0.o
            int r0 = (r3 > r0 ? 1 : (r3 == r0 ? 0 : -1))
            if (r0 == 0) goto L17
            goto L53
        L17:
            assistantMode.enums.m r0 = assistantMode.enums.m.d
            r1 = 1
            if (r9 != r0) goto L39
            kotlin.u r0 = r6.l
            java.lang.Object r0 = r0.getValue()
            assistantMode.refactored.modelTypes.DiagramShapeValue r0 = (assistantMode.refactored.modelTypes.DiagramShapeValue) r0
            if (r0 != 0) goto L28
            r0 = r1
            goto L29
        L28:
            r0 = r2
        L29:
            kotlin.u r3 = r7.l
            java.lang.Object r3 = r3.getValue()
            assistantMode.refactored.modelTypes.DiagramShapeValue r3 = (assistantMode.refactored.modelTypes.DiagramShapeValue) r3
            if (r3 != 0) goto L35
            r3 = r1
            goto L36
        L35:
            r3 = r2
        L36:
            if (r0 == r3) goto L39
            goto L53
        L39:
            if (r10 != 0) goto L42
            boolean r8 = a(r7, r6, r8)
            if (r8 == 0) goto L42
            goto L53
        L42:
            if (r11 != 0) goto L4b
            boolean r7 = a(r7, r6, r9)
            if (r7 == 0) goto L4b
            goto L53
        L4b:
            if (r12 != 0) goto L54
            boolean r6 = r6.e(r9)
            if (r6 != 0) goto L54
        L53:
            return r2
        L54:
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: assistantMode.utils.g.e(assistantMode.types.a, assistantMode.types.a, assistantMode.enums.m, assistantMode.enums.m, boolean, boolean, boolean):boolean");
    }

    public static final boolean f(m cardSide) {
        Intrinsics.checkNotNullParameter(cardSide, "cardSide");
        return cardSide == m.b || cardSide == m.c;
    }

    public static final List g(ArrayList arrayList) {
        Double dValueOf;
        Intrinsics.checkNotNullParameter(arrayList, "<this>");
        Iterator it2 = arrayList.iterator();
        if (it2.hasNext()) {
            double dDoubleValue = ((Number) it2.next()).doubleValue();
            while (it2.hasNext()) {
                dDoubleValue = Math.max(dDoubleValue, ((Number) it2.next()).doubleValue());
            }
            dValueOf = Double.valueOf(dDoubleValue);
        } else {
            dValueOf = null;
        }
        Intrinsics.d(dValueOf);
        double dDoubleValue2 = dValueOf.doubleValue();
        if (dDoubleValue2 == 0.0d) {
            return arrayList;
        }
        ArrayList arrayList2 = new ArrayList(C.q(arrayList, 10));
        Iterator it3 = arrayList.iterator();
        while (it3.hasNext()) {
            arrayList2.add(Double.valueOf(((Number) it3.next()).doubleValue() / dDoubleValue2));
        }
        return arrayList2;
    }

    public static final String h(String str) {
        Intrinsics.checkNotNullParameter(str, "<this>");
        String lowerCase = StringsKt.g0(str).toString().toLowerCase(Locale.ROOT);
        Intrinsics.checkNotNullExpressionValue(lowerCase, "toLowerCase(...)");
        return lowerCase;
    }

    public static final String i(String str) {
        return (String) StringsKt.V(str, new char[]{'-'}).get(0);
    }

    public static final double j(C1454a c1454a, C1454a c1454a2, m mVar, LinkedHashMap linkedHashMap) {
        if (!f(mVar)) {
            return 0.0d;
        }
        String strD = d(c1454a, mVar, linkedHashMap);
        String strD2 = d(c1454a2, mVar, linkedHashMap);
        if ((strD == null) == (strD2 == null)) {
            if (strD == null || strD2 == null) {
                return 0.0d;
            }
            String strC = I.C(15, strD);
            String strC2 = I.C(15, strD2);
            int iC = j3.c(strC, strC2);
            if (strC.length() != 0) {
                return (iC * 1.0d) / Math.max(strC.length(), strC2.length());
            }
            if (strC2.length() == 0) {
                return 0.0d;
            }
        }
        return 1.0d;
    }

    public static final double k(C1454a c1454a, C1454a c1454a2, m mVar, LinkedHashMap linkedHashMap) {
        String strD = d(c1454a, mVar, linkedHashMap);
        String strD2 = d(c1454a2, mVar, linkedHashMap);
        if ((strD == null) == (strD2 == null)) {
            if (strD == null || strD2 == null) {
                return 0.0d;
            }
            int iAbs = Math.abs(strD.length() - strD2.length());
            if (strD.length() != 0) {
                return (iAbs * 1.0d) / Math.max(strD.length(), strD2.length());
            }
            if (strD2.length() == 0) {
                return 0.0d;
            }
        }
        return 1.0d;
    }

    public static final ArrayList l(List orderedCards, int i, boolean z, boolean z2, C1454a questionCard, m promptSide, m answerSide, boolean z3) {
        Intrinsics.checkNotNullParameter(orderedCards, "orderedCards");
        Intrinsics.checkNotNullParameter(questionCard, "questionCard");
        Intrinsics.checkNotNullParameter(promptSide, "promptSide");
        Intrinsics.checkNotNullParameter(answerSide, "answerSide");
        ArrayList arrayList = new ArrayList();
        Iterator it2 = orderedCards.iterator();
        while (it2.hasNext()) {
            C1454a c1454a = (C1454a) it2.next();
            if (e(c1454a, questionCard, promptSide, answerSide, false, false, false) && !b(arrayList, c1454a, answerSide) && !b(arrayList, c1454a, promptSide)) {
                arrayList.add(c1454a);
            }
            if (arrayList.size() >= i) {
                break;
            }
        }
        Iterator it3 = orderedCards.iterator();
        while (it3.hasNext()) {
            C1454a c1454a2 = (C1454a) it3.next();
            if (arrayList.size() >= i) {
                break;
            }
            if (e(c1454a2, questionCard, promptSide, answerSide, z, z2, z3) && (z2 || !b(arrayList, c1454a2, answerSide))) {
                if (z || !b(arrayList, c1454a2, promptSide)) {
                    if (!c1454a2.equals(questionCard) && !arrayList.contains(c1454a2)) {
                        arrayList.add(c1454a2);
                    }
                }
            }
        }
        return arrayList;
    }

    public static final double m(C1454a c1454a, C1454a c1454a2, m mVar) {
        if (!f(mVar)) {
            return 0.0d;
        }
        assistantMode.utils.classification.classifierTypes.a aVarB = c1454a.i(mVar).b();
        assistantMode.utils.classification.classifierTypes.a aVarB2 = c1454a2.i(mVar).b();
        assistantMode.utils.classification.classifierTypes.a[] elements = {aVarB, aVarB2};
        Intrinsics.checkNotNullParameter(elements, "elements");
        Set setT = C4933y.T(elements);
        assistantMode.utils.classification.classifierTypes.a[] elements2 = {assistantMode.utils.classification.classifierTypes.a.b, assistantMode.utils.classification.classifierTypes.a.c};
        Intrinsics.checkNotNullParameter(elements2, "elements");
        if (Intrinsics.b(setT, C4933y.T(elements2))) {
            return 0.75d;
        }
        return aVarB == aVarB2 ? 0.0d : 1.0d;
    }

    public static final ImageAttribute n(ImageValue imageValue) {
        Intrinsics.checkNotNullParameter(imageValue, "<this>");
        return new ImageAttribute(imageValue.a, imageValue.b, imageValue.c);
    }

    public static final ArrayList o(List list) {
        boolean z;
        List listB;
        String str;
        String str2;
        Intrinsics.checkNotNullParameter(list, "<this>");
        if (list == null || !list.isEmpty()) {
            Iterator it2 = list.iterator();
            while (it2.hasNext()) {
                if (((assistantMode.refactored.modelTypes.c) it2.next()) instanceof AudioValue) {
                    z = true;
                    break;
                }
            }
            z = false;
        } else {
            z = false;
        }
        ArrayList arrayList = new ArrayList();
        Iterator it3 = list.iterator();
        while (it3.hasNext()) {
            assistantMode.refactored.modelTypes.c cVar = (assistantMode.refactored.modelTypes.c) it3.next();
            if (cVar instanceof TextValue) {
                TextValue textValue = (TextValue) cVar;
                TextAttribute textAttribute = new TextAttribute(textValue.a, textValue.b, textValue.e);
                listB = (z || (str = textValue.c) == null || (str2 = textValue.d) == null) ? A.b(textAttribute) : B.j(textAttribute, new AudioAttribute(str, str2));
            } else if (cVar instanceof ImageValue) {
                listB = A.b(n((ImageValue) cVar));
            } else if (cVar instanceof AudioValue) {
                String str3 = ((AudioValue) cVar).a;
                listB = A.b(new AudioAttribute(str3, str3));
            } else {
                if (!(cVar instanceof VideoValue)) {
                    if (cVar instanceof DiagramShapeValue) {
                        throw new IllegalArgumentException("DiagramShapeValues are not supported at this time");
                    }
                    throw new NoWhenBranchMatchedException();
                }
                VideoValue videoValue = (VideoValue) cVar;
                Intrinsics.checkNotNullParameter(videoValue, "<this>");
                listB = A.b(new VideoAttribute(videoValue.a, videoValue.b, videoValue.c, videoValue.d));
            }
            G.u(arrayList, listB);
        }
        return arrayList;
    }

    public static final assistantMode.types.C p(Set set) {
        Intrinsics.checkNotNullParameter(set, "<this>");
        return set.size() == 1 ? new OptionIndexAnswer(((Number) CollectionsKt.i0(set)).intValue()) : new OptionIndicesAnswer(set);
    }
}

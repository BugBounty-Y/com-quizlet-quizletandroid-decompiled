package androidx.compose.runtime.internal;

import android.os.Trace;
import androidx.collection.C0222u;
import androidx.collection.J;
import androidx.collection.L;
import androidx.collection.M;
import androidx.compose.runtime.C0836x0;
import androidx.compose.runtime.InterfaceC0802j;
import androidx.compose.runtime.InterfaceC0834w0;
import assistantMode.enums.s;
import assistantMode.refactored.modelTypes.TextValue;
import assistantMode.refactored.types.CardSideQuestionTypeRecommendation;
import assistantMode.refactored.types.FillInTheBlankKeyphraseLocation;
import assistantMode.refactored.types.FillInTheBlankQuestionStudiableMetadata;
import assistantMode.refactored.types.MLMCQDistractorStudiableMetadata;
import assistantMode.types.C1454a;
import assistantMode.types.C1457d;
import assistantMode.types.C1459f;
import assistantMode.types.test.TestSettings;
import com.google.android.gms.internal.mlkit_vision_barcode.W4;
import com.google.android.gms.internal.mlkit_vision_camera.o3;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.collections.A;
import kotlin.collections.B;
import kotlin.collections.C;
import kotlin.collections.CollectionsKt;
import kotlin.collections.G;
import kotlin.collections.K;
import kotlin.collections.U;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class j {
    public Object a;
    public Object b;
    public Object c;
    public Object d;
    public Object e;
    public Object f;
    public Object g;
    public Object h;
    public Object i;
    public Object j;

    public j() {
        this.j = new androidx.navigation.internal.m();
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    public static boolean t(C1457d cardEdge, assistantMode.utils.h dataSource, assistantMode.enums.k kVar) {
        List list;
        FillInTheBlankKeyphraseLocation fillInTheBlankKeyphraseLocation;
        int i;
        int i2;
        assistantMode.enums.m cardSide = cardEdge.b;
        assistantMode.enums.m answerSide = cardEdge.c;
        List listJ = B.j(cardSide, answerSide);
        C1454a card = cardEdge.a;
        if (card.f(listJ)) {
            int iOrdinal = kVar.ordinal();
            if (iOrdinal != 0) {
                if (iOrdinal != 1) {
                    if (iOrdinal == 2) {
                        card.getClass();
                        Intrinsics.checkNotNullParameter(answerSide, "answerSide");
                        Intrinsics.checkNotNullParameter(answerSide, "answerSide");
                        List listC = null;
                        assistantMode.utils.parsing.a aVar = card.i;
                        if ((aVar != null ? aVar.d : null) == answerSide) {
                            ArrayList arrayListD = o3.d(aVar);
                            ArrayList arrayList = new ArrayList(C.q(arrayListD, 10));
                            Iterator it2 = arrayListD.iterator();
                            while (it2.hasNext()) {
                                arrayList.add(o3.e((assistantMode.utils.parsing.b) it2.next(), (aVar.d == assistantMode.enums.m.b ? card.b : card.c).c()));
                            }
                            listC = arrayList;
                        }
                        if (listC == null && (listC = card.c(answerSide)) == null) {
                            listC = K.a;
                        }
                        if (listC.isEmpty()) {
                            MLMCQDistractorStudiableMetadata mLMCQDistractorStudiableMetadataF = dataSource.f(card.a.a, answerSide);
                            if (((mLMCQDistractorStudiableMetadataF == null || (list = mLMCQDistractorStudiableMetadataF.h) == null) ? false : !list.isEmpty()) || dataSource.k(answerSide)) {
                            }
                        }
                    } else if (iOrdinal != 3) {
                        if (iOrdinal != 4) {
                            switch (iOrdinal) {
                                case 10:
                                    dataSource.getClass();
                                    Intrinsics.checkNotNullParameter(cardEdge, "cardEdge");
                                    FillInTheBlankQuestionStudiableMetadata fillInTheBlankQuestionStudiableMetadataE = dataSource.e(cardEdge);
                                    if (fillInTheBlankQuestionStudiableMetadataE != null) {
                                        List list2 = fillInTheBlankQuestionStudiableMetadataE.h;
                                        if (!list2.isEmpty()) {
                                            String promptText = card.i(answerSide).e();
                                            Intrinsics.checkNotNullParameter(fillInTheBlankQuestionStudiableMetadataE, "<this>");
                                            Intrinsics.checkNotNullParameter(promptText, "promptText");
                                            if (!list2.isEmpty()) {
                                                Iterator it3 = list2.iterator();
                                                if (it3.hasNext() && (i2 = fillInTheBlankKeyphraseLocation.b + (i = (fillInTheBlankKeyphraseLocation = (FillInTheBlankKeyphraseLocation) it3.next()).a)) <= promptText.length()) {
                                                    assistantMode.refactored.modelTypes.c cVar = fillInTheBlankQuestionStudiableMetadataE.g;
                                                    Intrinsics.e(cVar, "null cannot be cast to non-null type assistantMode.refactored.modelTypes.TextValue");
                                                    String strH = assistantMode.utils.g.h(((TextValue) cVar).a);
                                                    String strSubstring = promptText.substring(i, i2);
                                                    Intrinsics.checkNotNullExpressionValue(strSubstring, "substring(...)");
                                                    return Intrinsics.b(strH, assistantMode.utils.g.h(strSubstring));
                                                }
                                            }
                                        }
                                    }
                                    break;
                                case 11:
                                    dataSource.getClass();
                                    Intrinsics.checkNotNullParameter(cardEdge, "cardEdge");
                                    if (dataSource.g(cardEdge) != null) {
                                    }
                                    break;
                                case 12:
                                    if (card.i == null) {
                                        dataSource.getClass();
                                        Intrinsics.checkNotNullParameter(cardEdge, "cardEdge");
                                        if (!dataSource.d(cardEdge).isEmpty()) {
                                        }
                                    }
                                    break;
                            }
                        }
                    } else if (dataSource.k(answerSide)) {
                        Intrinsics.checkNotNullParameter(card, "card");
                        Intrinsics.checkNotNullParameter(cardSide, "cardSide");
                        Intrinsics.checkNotNullParameter(dataSource, "dataSource");
                        int iOrdinal2 = cardSide.ordinal();
                        if (iOrdinal2 != 0) {
                            if (iOrdinal2 != 1) {
                                if (iOrdinal2 != 2) {
                                    throw new NoWhenBranchMatchedException();
                                }
                            } else if (dataSource.c(card, assistantMode.enums.m.c).size() == 1) {
                            }
                        } else if (dataSource.c(card, assistantMode.enums.m.b).size() == 1) {
                        }
                    }
                }
                return true;
            }
            if (card.f(B.j(cardSide, answerSide)) && card.a(answerSide)) {
                return true;
            }
        }
        return false;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r1v0, types: [kotlin.collections.K] */
    /* JADX WARN: Type inference failed for: r1v1, types: [java.lang.Iterable] */
    /* JADX WARN: Type inference failed for: r1v2, types: [java.util.ArrayList] */
    public static final ArrayList x(assistantMode.enums.m mVar, List list) {
        ?? arrayList;
        List listB = A.b(mVar);
        if (list != null) {
            arrayList = new ArrayList();
            for (Object obj : list) {
                if (((assistantMode.enums.m) obj) != mVar) {
                    arrayList.add(obj);
                }
            }
        } else {
            arrayList = K.a;
        }
        return CollectionsKt.c0(listB, arrayList);
    }

    public void a(String str, String str2) {
        HashMap map = (HashMap) this.f;
        if (map == null) {
            throw new IllegalStateException("Property \"autoMetadata\" has not been set");
        }
        map.put(str, str2);
    }

    public com.google.android.datatransport.runtime.h b() {
        String strK = ((String) this.a) == null ? " transportName" : "";
        if (((com.google.android.datatransport.runtime.k) this.c) == null) {
            strK = strK.concat(" encodedPayload");
        }
        if (((Long) this.d) == null) {
            strK = android.support.v4.media.session.a.k(strK, " eventMillis");
        }
        if (((Long) this.e) == null) {
            strK = android.support.v4.media.session.a.k(strK, " uptimeMillis");
        }
        if (((HashMap) this.f) == null) {
            strK = android.support.v4.media.session.a.k(strK, " autoMetadata");
        }
        if (strK.isEmpty()) {
            return new com.google.android.datatransport.runtime.h((String) this.a, (Integer) this.b, (com.google.android.datatransport.runtime.k) this.c, ((Long) this.d).longValue(), ((Long) this.e).longValue(), (HashMap) this.f, (Integer) this.g, (String) this.h, (byte[]) this.i, (byte[]) this.j);
        }
        throw new IllegalStateException("Missing required properties:".concat(strK));
    }

    public void c() {
        M m = (M) this.a;
        if (m.isEmpty()) {
            return;
        }
        Trace.beginSection("Compose:abandons");
        try {
            m.getClass();
            L l = new L(m);
            kotlin.sequences.h hVar = (kotlin.sequences.h) l.c;
            while (hVar.hasNext()) {
                InterfaceC0834w0 interfaceC0834w0 = (InterfaceC0834w0) hVar.next();
                l.remove();
                interfaceC0834w0.a();
            }
            Unit unit = Unit.a;
            Trace.endSection();
        } catch (Throwable th) {
            Trace.endSection();
            throw th;
        }
    }

    public void d() {
        v(Integer.MIN_VALUE);
        androidx.compose.runtime.collection.b bVar = (androidx.compose.runtime.collection.b) this.d;
        int i = bVar.c;
        M m = (M) this.a;
        if (i != 0) {
            Trace.beginSection("Compose:onForgotten");
            try {
                J j = (J) this.f;
                for (int i2 = bVar.c - 1; -1 < i2; i2--) {
                    Object obj = bVar.a[i2];
                    if (obj instanceof C0836x0) {
                        InterfaceC0834w0 interfaceC0834w0 = ((C0836x0) obj).a;
                        m.remove(interfaceC0834w0);
                        interfaceC0834w0.b();
                    }
                    if (obj instanceof InterfaceC0802j) {
                        if (j == null || !j.c(obj)) {
                            ((InterfaceC0802j) obj).b();
                        } else {
                            ((InterfaceC0802j) obj).a();
                        }
                    }
                }
                Unit unit = Unit.a;
            } finally {
            }
        }
        androidx.compose.runtime.collection.b bVar2 = (androidx.compose.runtime.collection.b) this.b;
        if (bVar2.c != 0) {
            Trace.beginSection("Compose:onRemembered");
            try {
                Object[] objArr = bVar2.a;
                int i3 = bVar2.c;
                for (int i4 = 0; i4 < i3; i4++) {
                    InterfaceC0834w0 interfaceC0834w02 = ((C0836x0) objArr[i4]).a;
                    m.remove(interfaceC0834w02);
                    interfaceC0834w02.d();
                }
                Unit unit2 = Unit.a;
            } finally {
                Trace.endSection();
            }
        }
    }

    public Set e() {
        Set set = (Set) this.i;
        ArrayList arrayList = new ArrayList(C.q(set, 10));
        Iterator it2 = set.iterator();
        while (it2.hasNext()) {
            arrayList.add(Long.valueOf(((C1459f) it2.next()).a));
        }
        return CollectionsKt.A0(arrayList);
    }

    public int f(long j, assistantMode.enums.k questionType, assistantMode.enums.m answerSide) {
        Intrinsics.checkNotNullParameter(questionType, "questionType");
        Intrinsics.checkNotNullParameter(answerSide, "answerSide");
        List listK = k(j, questionType);
        if (listK == null) {
            return 0;
        }
        if (listK.contains(answerSide)) {
            return listK.indexOf(answerSide);
        }
        return 999;
    }

    /* JADX WARN: Code restructure failed: missing block: B:24:0x005e, code lost:
    
        if (r7 == r1) goto L25;
     */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object g(kotlin.jvm.functions.Function1 r6, kotlin.coroutines.jvm.internal.c r7) {
        /*
            r5 = this;
            boolean r0 = r7 instanceof com.quizlet.login.common.interactors.e
            if (r0 == 0) goto L13
            r0 = r7
            com.quizlet.login.common.interactors.e r0 = (com.quizlet.login.common.interactors.e) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            com.quizlet.login.common.interactors.e r0 = new com.quizlet.login.common.interactors.e
            r0.<init>(r5, r7)
        L18:
            java.lang.Object r7 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 2
            r4 = 1
            if (r2 == 0) goto L38
            if (r2 == r4) goto L32
            if (r2 != r3) goto L2a
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L61
        L2a:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r7 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r7)
            throw r6
        L32:
            kotlin.jvm.functions.Function1 r6 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L4a
        L38:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            r0.j = r6
            r0.m = r4
            java.lang.Object r7 = r5.e
            com.google.firebase.crashlytics.internal.settings.b r7 = (com.google.firebase.crashlytics.internal.settings.b) r7
            java.lang.Object r7 = r7.d(r0)
            if (r7 != r1) goto L4a
            goto L60
        L4a:
            java.lang.Boolean r7 = (java.lang.Boolean) r7
            boolean r7 = r7.booleanValue()
            if (r7 == 0) goto L55
            com.quizlet.login.common.interactors.data.s r6 = com.quizlet.login.common.interactors.data.s.a
            return r6
        L55:
            r7 = 0
            r0.j = r7
            r0.m = r3
            java.lang.Object r7 = r6.invoke(r0)
            if (r7 != r1) goto L61
        L60:
            return r1
        L61:
            java.lang.Boolean r7 = (java.lang.Boolean) r7
            boolean r6 = r7.booleanValue()
            if (r6 == 0) goto L6c
            com.quizlet.login.common.interactors.data.x r6 = com.quizlet.login.common.interactors.data.x.a
            return r6
        L6c:
            com.quizlet.login.common.interactors.data.w r6 = com.quizlet.login.common.interactors.data.w.a
            return r6
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.runtime.internal.j.g(kotlin.jvm.functions.Function1, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public Set h(long j, assistantMode.enums.k questionType) {
        Intrinsics.checkNotNullParameter(questionType, "questionType");
        Set set = (Set) this.i;
        ArrayList arrayList = new ArrayList();
        for (Object obj : set) {
            C1459f c1459f = (C1459f) obj;
            if (c1459f.a == j && c1459f.d == questionType) {
                arrayList.add(obj);
            }
        }
        return CollectionsKt.A0(arrayList);
    }

    public Set i(long j) {
        Set<assistantMode.enums.m> set = (Set) this.b;
        ArrayList arrayList = new ArrayList();
        for (assistantMode.enums.m mVar : set) {
            Set set2 = (Set) this.c;
            ArrayList arrayList2 = new ArrayList(C.q(set2, 10));
            Iterator it2 = set2.iterator();
            while (it2.hasNext()) {
                arrayList2.add(j(j, mVar, (assistantMode.enums.m) it2.next()));
            }
            G.u(arrayList, arrayList2);
        }
        Iterator it3 = arrayList.iterator();
        if (!it3.hasNext()) {
            throw new UnsupportedOperationException("Empty collection can't be reduced.");
        }
        Object next = it3.next();
        while (it3.hasNext()) {
            next = CollectionsKt.B0((Set) next, (Set) it3.next());
        }
        return (Set) next;
    }

    public Set j(long j, assistantMode.enums.m promptSide, assistantMode.enums.m answerSide) {
        Set set;
        Intrinsics.checkNotNullParameter(promptSide, "promptSide");
        Intrinsics.checkNotNullParameter(answerSide, "answerSide");
        Object obj = ((LinkedHashMap) this.h).get(Long.valueOf(j));
        if (obj == null) {
            throw new IllegalArgumentException("Required value was null.");
        }
        Map map = (Map) ((Map) obj).get(answerSide);
        return (map == null || (set = (Set) map.get(promptSide)) == null) ? kotlin.collections.M.a : set;
    }

    /* JADX WARN: Removed duplicated region for block: B:22:0x0058  */
    /* JADX WARN: Removed duplicated region for block: B:43:0x00a0  */
    /* JADX WARN: Removed duplicated region for block: B:48:0x00ae  */
    /* JADX WARN: Removed duplicated region for block: B:51:0x00bf  */
    /* JADX WARN: Removed duplicated region for block: B:6:0x0029  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.util.List k(long r10, assistantMode.enums.k r12) {
        /*
            r9 = this;
            java.lang.String r0 = "questionType"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r12, r0)
            java.lang.Object r0 = r9.j
            java.util.LinkedHashMap r0 = (java.util.LinkedHashMap) r0
            kotlin.Pair r1 = new kotlin.Pair
            java.lang.Long r2 = java.lang.Long.valueOf(r10)
            r1.<init>(r2, r12)
            java.lang.Object r2 = r0.get(r1)
            if (r2 != 0) goto Ld6
            java.lang.Object r2 = r9.g
            java.util.LinkedHashMap r2 = (java.util.LinkedHashMap) r2
            java.lang.Long r3 = java.lang.Long.valueOf(r10)
            java.lang.Object r2 = r2.get(r3)
            assistantMode.refactored.types.CardSideQuestionTypeRecommendation r2 = (assistantMode.refactored.types.CardSideQuestionTypeRecommendation) r2
            r3 = 0
            if (r2 != 0) goto L2b
        L29:
            r2 = r3
            goto L40
        L2b:
            int r4 = r12.ordinal()
            if (r4 == 0) goto L3e
            r5 = 2
            if (r4 == r5) goto L3b
            r5 = 4
            if (r4 == r5) goto L38
            goto L29
        L38:
            assistantMode.refactored.types.AnswerSidePriorities r2 = r2.i
            goto L40
        L3b:
            assistantMode.refactored.types.AnswerSidePriorities r2 = r2.g
            goto L40
        L3e:
            assistantMode.refactored.types.AnswerSidePriorities r2 = r2.h
        L40:
            if (r2 == 0) goto L45
            java.util.List r4 = r2.a
            goto L46
        L45:
            r4 = r3
        L46:
            java.lang.Object r5 = r9.a
            assistantMode.utils.h r5 = (assistantMode.utils.h) r5
            java.util.LinkedHashMap r5 = r5.f
            java.lang.Long r10 = java.lang.Long.valueOf(r10)
            java.lang.Object r10 = r5.get(r10)
            assistantMode.types.a r10 = (assistantMode.types.C1454a) r10
            if (r10 != 0) goto L5b
        L58:
            r2 = r4
            goto Ld3
        L5b:
            assistantMode.enums.k r11 = assistantMode.enums.k.d
            r5 = 1
            if (r12 != r11) goto L91
            kotlin.u r11 = r10.l
            java.lang.Object r11 = r11.getValue()
            assistantMode.refactored.modelTypes.DiagramShapeValue r11 = (assistantMode.refactored.modelTypes.DiagramShapeValue) r11
            if (r11 == 0) goto L72
            assistantMode.enums.m r10 = assistantMode.enums.m.d
            java.util.ArrayList r10 = x(r10, r4)
        L70:
            r2 = r10
            goto Ld3
        L72:
            assistantMode.enums.m[] r11 = assistantMode.enums.m.values()
            int r12 = r11.length
            r6 = 0
        L78:
            if (r6 >= r12) goto L91
            r7 = r11[r6]
            java.util.List r8 = r10.c(r7)
            if (r8 == 0) goto L8e
            boolean r8 = r8.isEmpty()
            r8 = r8 ^ r5
            if (r8 != r5) goto L8e
            java.util.ArrayList r10 = x(r7, r4)
            goto L70
        L8e:
            int r6 = r6 + 1
            goto L78
        L91:
            assistantMode.enums.m r10 = r10.k
            if (r10 == 0) goto La0
            if (r2 == 0) goto La0
            boolean r11 = r2.b
            if (r11 != r5) goto La0
            java.util.ArrayList r10 = x(r10, r4)
            goto L70
        La0:
            if (r4 == 0) goto La8
            boolean r10 = r4.isEmpty()
            if (r10 == 0) goto L58
        La8:
            java.lang.Object r10 = r9.e
            java.util.Set r10 = (java.util.Set) r10
            if (r10 == 0) goto Lbf
            assistantMode.enums.m r11 = assistantMode.enums.m.c
            boolean r12 = r10.contains(r11)
            if (r12 != r5) goto Lbf
            assistantMode.enums.m[] r10 = new assistantMode.enums.m[]{r11}
            java.util.ArrayList r10 = kotlin.collections.B.k(r10)
            goto L70
        Lbf:
            if (r10 == 0) goto Ld2
            assistantMode.enums.m r11 = assistantMode.enums.m.b
            boolean r10 = r10.contains(r11)
            if (r10 != r5) goto Ld2
            assistantMode.enums.m[] r10 = new assistantMode.enums.m[]{r11}
            java.util.ArrayList r10 = kotlin.collections.B.k(r10)
            goto L70
        Ld2:
            r2 = r3
        Ld3:
            r0.put(r1, r2)
        Ld6:
            java.util.List r2 = (java.util.List) r2
            return r2
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.runtime.internal.j.k(long, assistantMode.enums.k):java.util.List");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object l(long r7, com.quizlet.infra.legacysyncengine.features.properties.d r9, kotlin.coroutines.jvm.internal.c r10) {
        /*
            r6 = this;
            boolean r0 = r10 instanceof com.quizlet.features.setpage.usecases.a
            if (r0 == 0) goto L13
            r0 = r10
            com.quizlet.features.setpage.usecases.a r0 = (com.quizlet.features.setpage.usecases.a) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.quizlet.features.setpage.usecases.a r0 = new com.quizlet.features.setpage.usecases.a
            r0.<init>(r6, r10)
        L18:
            java.lang.Object r10 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L2f
            if (r2 != r3) goto L27
            androidx.glance.appwidget.protobuf.Z.e(r10)
            goto L4d
        L27:
            java.lang.IllegalStateException r7 = new java.lang.IllegalStateException
            java.lang.String r8 = "call to 'resume' before 'invoke' with coroutine"
            r7.<init>(r8)
            throw r7
        L2f:
            androidx.glance.appwidget.protobuf.Z.e(r10)
            r4 = 0
            int r7 = (r7 > r4 ? 1 : (r7 == r4 ? 0 : -1))
            if (r7 <= 0) goto L52
            r0.l = r3
            java.lang.Object r7 = r6.e
            com.quizlet.data.repository.activitycenter.b r7 = (com.quizlet.data.repository.activitycenter.b) r7
            java.lang.Object r8 = r6.b
            androidx.work.impl.model.c r8 = (androidx.work.impl.model.c) r8
            io.reactivex.rxjava3.internal.operators.single.g r7 = r7.g(r8, r9)
            java.lang.Object r10 = com.google.android.gms.internal.mlkit_vision_camera.I1.b(r7, r0)
            if (r10 != r1) goto L4d
            return r1
        L4d:
            com.quizlet.features.infra.basestudy.data.models.shareset.a r7 = com.quizlet.features.infra.basestudy.data.models.shareset.a.d
            if (r10 == r7) goto L52
            goto L53
        L52:
            r3 = 0
        L53:
            java.lang.Boolean r7 = java.lang.Boolean.valueOf(r3)
            return r7
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.runtime.internal.j.l(long, com.quizlet.infra.legacysyncengine.features.properties.d, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object m(com.quizlet.data.model.Z1 r7, kotlin.coroutines.jvm.internal.c r8) {
        /*
            r6 = this;
            boolean r0 = r8 instanceof com.quizlet.features.setpage.usecases.b
            if (r0 == 0) goto L13
            r0 = r8
            com.quizlet.features.setpage.usecases.b r0 = (com.quizlet.features.setpage.usecases.b) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            com.quizlet.features.setpage.usecases.b r0 = new com.quizlet.features.setpage.usecases.b
            r0.<init>(r6, r8)
        L18:
            java.lang.Object r8 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 1
            if (r2 == 0) goto L31
            if (r2 != r3) goto L29
            java.lang.Long r7 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L55
        L29:
            java.lang.IllegalStateException r7 = new java.lang.IllegalStateException
            java.lang.String r8 = "call to 'resume' before 'invoke' with coroutine"
            r7.<init>(r8)
            throw r7
        L31:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            com.quizlet.data.model.User r7 = r7.b
            if (r7 == 0) goto L41
            java.lang.Long r8 = new java.lang.Long
            long r4 = r7.a
            r8.<init>(r4)
            r7 = r8
            goto L42
        L41:
            r7 = 0
        L42:
            java.lang.Object r8 = r6.b
            androidx.work.impl.model.c r8 = (androidx.work.impl.model.c) r8
            io.reactivex.rxjava3.internal.operators.single.g r8 = r8.n()
            r0.j = r7
            r0.m = r3
            java.lang.Object r8 = com.google.android.gms.internal.mlkit_vision_camera.I1.b(r8, r0)
            if (r8 != r1) goto L55
            return r1
        L55:
            boolean r7 = kotlin.jvm.internal.Intrinsics.b(r7, r8)
            java.lang.Boolean r7 = java.lang.Boolean.valueOf(r7)
            return r7
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.runtime.internal.j.m(com.quizlet.data.model.Z1, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object n(com.quizlet.data.model.Z1 r7, kotlin.coroutines.jvm.internal.c r8) {
        /*
            r6 = this;
            boolean r0 = r8 instanceof com.quizlet.features.setpage.usecases.c
            if (r0 == 0) goto L13
            r0 = r8
            com.quizlet.features.setpage.usecases.c r0 = (com.quizlet.features.setpage.usecases.c) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            com.quizlet.features.setpage.usecases.c r0 = new com.quizlet.features.setpage.usecases.c
            r0.<init>(r6, r8)
        L18:
            java.lang.Object r8 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 1
            if (r2 == 0) goto L31
            if (r2 != r3) goto L29
            java.lang.Long r7 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L5c
        L29:
            java.lang.IllegalStateException r7 = new java.lang.IllegalStateException
            java.lang.String r8 = "call to 'resume' before 'invoke' with coroutine"
            r7.<init>(r8)
            throw r7
        L31:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            com.quizlet.data.model.User r7 = r7.b
            if (r7 == 0) goto L3d
            boolean r8 = r7.e
            if (r8 != r3) goto L3d
            goto L63
        L3d:
            if (r7 == 0) goto L48
            java.lang.Long r8 = new java.lang.Long
            long r4 = r7.a
            r8.<init>(r4)
            r7 = r8
            goto L49
        L48:
            r7 = 0
        L49:
            java.lang.Object r8 = r6.b
            androidx.work.impl.model.c r8 = (androidx.work.impl.model.c) r8
            io.reactivex.rxjava3.internal.operators.single.g r8 = r8.n()
            r0.j = r7
            r0.m = r3
            java.lang.Object r8 = com.google.android.gms.internal.mlkit_vision_camera.I1.b(r8, r0)
            if (r8 != r1) goto L5c
            return r1
        L5c:
            boolean r7 = kotlin.jvm.internal.Intrinsics.b(r7, r8)
            if (r7 != 0) goto L63
            goto L64
        L63:
            r3 = 0
        L64:
            java.lang.Boolean r7 = java.lang.Boolean.valueOf(r3)
            return r7
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.runtime.internal.j.n(com.quizlet.data.model.Z1, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Code restructure failed: missing block: B:22:0x0064, code lost:
    
        if (r6 == r1) goto L23;
     */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object o(kotlin.coroutines.jvm.internal.c r6) {
        /*
            r5 = this;
            boolean r0 = r6 instanceof com.quizlet.features.setpage.usecases.d
            if (r0 == 0) goto L13
            r0 = r6
            com.quizlet.features.setpage.usecases.d r0 = (com.quizlet.features.setpage.usecases.d) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            com.quizlet.features.setpage.usecases.d r0 = new com.quizlet.features.setpage.usecases.d
            r0.<init>(r5, r6)
        L18:
            java.lang.Object r6 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 2
            r4 = 1
            if (r2 == 0) goto L38
            if (r2 == r4) goto L32
            if (r2 != r3) goto L2a
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L67
        L2a:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r0)
            throw r6
        L32:
            androidx.work.impl.model.c r2 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L4f
        L38:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            java.lang.Object r6 = r5.b
            r2 = r6
            androidx.work.impl.model.c r2 = (androidx.work.impl.model.c) r2
            io.reactivex.rxjava3.internal.operators.single.g r6 = r2.r()
            r0.j = r2
            r0.m = r4
            java.lang.Object r6 = com.google.android.gms.internal.mlkit_vision_camera.I1.b(r6, r0)
            if (r6 != r1) goto L4f
            goto L66
        L4f:
            java.lang.Boolean r6 = (java.lang.Boolean) r6
            boolean r6 = r6.booleanValue()
            if (r6 != 0) goto L70
            io.reactivex.rxjava3.internal.operators.single.g r6 = r2.u()
            r2 = 0
            r0.j = r2
            r0.m = r3
            java.lang.Object r6 = com.google.android.gms.internal.mlkit_vision_camera.I1.b(r6, r0)
            if (r6 != r1) goto L67
        L66:
            return r1
        L67:
            java.lang.Boolean r6 = (java.lang.Boolean) r6
            boolean r6 = r6.booleanValue()
            if (r6 != 0) goto L70
            goto L71
        L70:
            r4 = 0
        L71:
            java.lang.Boolean r6 = java.lang.Boolean.valueOf(r4)
            return r6
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.runtime.internal.j.o(kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object p(java.lang.String r5, kotlin.coroutines.jvm.internal.c r6) {
        /*
            r4 = this;
            boolean r0 = r6 instanceof com.quizlet.login.common.interactors.f
            if (r0 == 0) goto L13
            r0 = r6
            com.quizlet.login.common.interactors.f r0 = (com.quizlet.login.common.interactors.f) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.quizlet.login.common.interactors.f r0 = new com.quizlet.login.common.interactors.f
            r0.<init>(r4, r6)
        L18:
            java.lang.Object r6 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L2f
            if (r2 != r3) goto L27
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L41
        L27:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L2f:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            if (r5 == 0) goto L44
            r0.l = r3
            java.lang.Object r6 = r4.f
            com.google.mlkit.vision.documentscanner.internal.c r6 = (com.google.mlkit.vision.documentscanner.internal.c) r6
            java.lang.Object r5 = r6.n(r5, r0)
            if (r5 != r1) goto L41
            return r1
        L41:
            com.quizlet.login.common.interactors.data.t r5 = com.quizlet.login.common.interactors.data.t.a
            return r5
        L44:
            com.quizlet.login.common.interactors.data.o r5 = com.quizlet.login.common.interactors.data.o.a
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.runtime.internal.j.p(java.lang.String, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:7:0x001b  */
    /* JADX WARN: Type inference failed for: r3v3 */
    /* JADX WARN: Type inference failed for: r3v4, types: [boolean, int] */
    /* JADX WARN: Type inference failed for: r3v6 */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object q(java.lang.String r20, com.quizlet.db.data.models.persisted.DBUser r21, boolean r22, java.lang.String r23, kotlin.coroutines.jvm.internal.c r24) {
        /*
            Method dump skipped, instructions count: 238
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.runtime.internal.j.q(java.lang.String, com.quizlet.db.data.models.persisted.DBUser, boolean, java.lang.String, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:28:0x0116  */
    /* JADX WARN: Removed duplicated region for block: B:30:0x0119  */
    /* JADX WARN: Removed duplicated region for block: B:57:0x01b4  */
    /* JADX WARN: Removed duplicated region for block: B:61:0x01e9  */
    /* JADX WARN: Removed duplicated region for block: B:65:0x020e  */
    /* JADX WARN: Removed duplicated region for block: B:69:0x0236  */
    /* JADX WARN: Removed duplicated region for block: B:73:0x0295  */
    /* JADX WARN: Removed duplicated region for block: B:77:0x02e3  */
    /* JADX WARN: Removed duplicated region for block: B:81:0x031c  */
    /* JADX WARN: Removed duplicated region for block: B:8:0x001a  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.io.Serializable r(long r20, kotlin.coroutines.jvm.internal.c r22) throws java.lang.Throwable {
        /*
            Method dump skipped, instructions count: 894
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.runtime.internal.j.r(long, kotlin.coroutines.jvm.internal.c):java.io.Serializable");
    }

    /* JADX WARN: Removed duplicated region for block: B:8:0x0014  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object s(com.quizlet.login.authentication.data.i r10, java.lang.String r11, java.lang.String r12, kotlin.coroutines.jvm.internal.c r13) {
        /*
            Method dump skipped, instructions count: 359
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.runtime.internal.j.s(com.quizlet.login.authentication.data.i, java.lang.String, java.lang.String, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0019  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object u(com.quizlet.db.data.models.persisted.DBUser r17, java.lang.String r18, kotlin.coroutines.jvm.internal.c r19) {
        /*
            r16 = this;
            r0 = r16
            r1 = r17
            r2 = r19
            boolean r3 = r2 instanceof com.quizlet.login.common.interactors.j
            if (r3 == 0) goto L19
            r3 = r2
            com.quizlet.login.common.interactors.j r3 = (com.quizlet.login.common.interactors.j) r3
            int r4 = r3.n
            r5 = -2147483648(0xffffffff80000000, float:-0.0)
            r6 = r4 & r5
            if (r6 == 0) goto L19
            int r4 = r4 - r5
            r3.n = r4
            goto L1e
        L19:
            com.quizlet.login.common.interactors.j r3 = new com.quizlet.login.common.interactors.j
            r3.<init>(r0, r2)
        L1e:
            java.lang.Object r2 = r3.l
            kotlin.coroutines.intrinsics.a r4 = kotlin.coroutines.intrinsics.a.a
            int r5 = r3.n
            r6 = 2
            r7 = 0
            r8 = 1
            if (r5 == 0) goto L42
            if (r5 == r8) goto L39
            if (r5 != r6) goto L31
            androidx.glance.appwidget.protobuf.Z.e(r2)
            return r2
        L31:
            java.lang.IllegalStateException r1 = new java.lang.IllegalStateException
            java.lang.String r2 = "call to 'resume' before 'invoke' with coroutine"
            r1.<init>(r2)
            throw r1
        L39:
            com.quizlet.login.common.interactors.k r1 = r3.k
            androidx.compose.runtime.internal.j r5 = r3.j
            androidx.glance.appwidget.protobuf.Z.e(r2)
            goto La7
        L42:
            androidx.glance.appwidget.protobuf.Z.e(r2)
            java.lang.Object r2 = r0.c
            com.google.android.gms.internal.appset.e r2 = (com.google.android.gms.internal.appset.e) r2
            r10 = r18
            r2.t(r10, r1)
            int r2 = r1.getSelfIdentifiedUserType()
            r5 = 0
            if (r2 != r8) goto L5d
            int r2 = r1.getUserUpgradeType()
            if (r2 != 0) goto L5d
            r2 = r8
            goto L5e
        L5d:
            r2 = r5
        L5e:
            java.lang.Boolean r12 = java.lang.Boolean.valueOf(r2)
            int r2 = r1.getUserUpgradeType()
            if (r2 != r8) goto L6a
            r2 = r8
            goto L6b
        L6a:
            r2 = r5
        L6b:
            java.lang.Boolean r13 = java.lang.Boolean.valueOf(r2)
            int r2 = r1.getUserUpgradeType()
            if (r2 == 0) goto L76
            r5 = r8
        L76:
            java.lang.Boolean r14 = java.lang.Boolean.valueOf(r5)
            boolean r2 = r1.getIsUnderAge()
            java.lang.Boolean r15 = java.lang.Boolean.valueOf(r2)
            java.lang.Object r2 = r0.i
            r9 = r2
            com.quizlet.quizletandroid.ui.login.h r9 = (com.quizlet.quizletandroid.ui.login.h) r9
            r11 = 1
            com.quizlet.quizletandroid.ui.login.h.i(r9, r10, r11, r12, r13, r14, r15)
            com.quizlet.login.common.interactors.k r2 = new com.quizlet.login.common.interactors.k
            r2.<init>(r0, r1, r7)
            long r9 = r1.getId()
            r3.j = r0
            r3.k = r2
            r3.n = r8
            java.lang.Object r1 = r0.j
            com.google.firebase.crashlytics.internal.common.j r1 = (com.google.firebase.crashlytics.internal.common.j) r1
            java.lang.Object r1 = r1.e(r9, r3)
            if (r1 != r4) goto La5
            goto Lb3
        La5:
            r5 = r0
            r1 = r2
        La7:
            r3.j = r7
            r3.k = r7
            r3.n = r6
            java.lang.Object r1 = r5.g(r1, r3)
            if (r1 != r4) goto Lb4
        Lb3:
            return r4
        Lb4:
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.runtime.internal.j.u(com.quizlet.db.data.models.persisted.DBUser, java.lang.String, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public void v(int i) {
        ArrayList arrayList = (ArrayList) this.g;
        if (arrayList.isEmpty()) {
            return;
        }
        int i2 = 0;
        ArrayList arrayListK = null;
        int i3 = 0;
        C0222u c0222u = null;
        C0222u c0222u2 = null;
        while (true) {
            C0222u c0222u3 = (C0222u) this.j;
            if (i3 >= c0222u3.b) {
                break;
            }
            if (i <= c0222u3.c(i3)) {
                Object objRemove = arrayList.remove(i3);
                int iF = c0222u3.f(i3);
                int iF2 = ((C0222u) this.i).f(i3);
                if (arrayListK == null) {
                    arrayListK = B.k(objRemove);
                    c0222u2 = new C0222u();
                    c0222u2.a(iF);
                    c0222u = new C0222u();
                    c0222u.a(iF2);
                } else {
                    Intrinsics.e(c0222u, "null cannot be cast to non-null type androidx.collection.MutableIntList");
                    Intrinsics.e(c0222u2, "null cannot be cast to non-null type androidx.collection.MutableIntList");
                    arrayListK.add(objRemove);
                    c0222u2.a(iF);
                    c0222u.a(iF2);
                }
            } else {
                i3++;
            }
        }
        if (arrayListK != null) {
            Intrinsics.e(c0222u, "null cannot be cast to non-null type androidx.collection.MutableIntList");
            Intrinsics.e(c0222u2, "null cannot be cast to non-null type androidx.collection.MutableIntList");
            int size = arrayListK.size() - 1;
            while (i2 < size) {
                int i4 = i2 + 1;
                int size2 = arrayListK.size();
                for (int i5 = i4; i5 < size2; i5++) {
                    int iC = c0222u2.c(i2);
                    int iC2 = c0222u2.c(i5);
                    if (iC < iC2 || (iC2 == iC && c0222u.c(i2) < c0222u.c(i5))) {
                        Object obj = arrayListK.get(i2);
                        arrayListK.set(i2, arrayListK.get(i5));
                        arrayListK.set(i5, obj);
                        int iC3 = c0222u.c(i2);
                        c0222u.g(i2, c0222u.c(i5));
                        c0222u.g(i5, iC3);
                        int iC4 = c0222u2.c(i2);
                        c0222u2.g(i2, c0222u2.c(i5));
                        c0222u2.g(i5, iC4);
                    }
                }
                i2 = i4;
            }
            androidx.compose.runtime.collection.b bVar = (androidx.compose.runtime.collection.b) this.d;
            bVar.e(bVar.c, arrayListK);
        }
    }

    public void w(Object obj, int i, int i2, int i3) {
        v(i);
        if (i3 < 0 || i3 >= i) {
            ((androidx.compose.runtime.collection.b) this.d).b(obj);
            return;
        }
        ((ArrayList) this.g).add(obj);
        ((C0222u) this.i).a(i2);
        ((C0222u) this.j).a(i3);
    }

    public j(assistantMode.utils.h studyableMaterialDataSource, Set enabledQuestionTypes, Set enabledPromptSides, Set enabledAnswerSides, Set enabledWrittenAnswerSides, Set enabledLocationQuestionTypes, Set set) {
        Intrinsics.checkNotNullParameter(studyableMaterialDataSource, "studyableMaterialDataSource");
        Intrinsics.checkNotNullParameter(enabledQuestionTypes, "enabledQuestionTypes");
        Intrinsics.checkNotNullParameter(enabledPromptSides, "enabledPromptSides");
        Intrinsics.checkNotNullParameter(enabledAnswerSides, "enabledAnswerSides");
        Intrinsics.checkNotNullParameter(enabledWrittenAnswerSides, "enabledWrittenAnswerSides");
        Intrinsics.checkNotNullParameter(enabledLocationQuestionTypes, "enabledLocationQuestionTypes");
        this.a = studyableMaterialDataSource;
        this.b = enabledPromptSides;
        this.c = enabledAnswerSides;
        this.d = enabledLocationQuestionTypes;
        this.e = set;
        LinkedHashSet linkedHashSetZ0 = CollectionsKt.z0(enabledQuestionTypes);
        if (enabledQuestionTypes.contains(assistantMode.enums.k.l)) {
            linkedHashSetZ0.add(assistantMode.enums.k.b);
        }
        this.f = linkedHashSetZ0;
        studyableMaterialDataSource.getClass();
        List listI = studyableMaterialDataSource.i(s.e);
        ArrayList arrayList = new ArrayList();
        for (Object obj : listI) {
            if (obj instanceof CardSideQuestionTypeRecommendation) {
                arrayList.add(obj);
            }
        }
        int i = 10;
        int iA = U.a(C.q(arrayList, 10));
        int i2 = 16;
        LinkedHashMap linkedHashMap = new LinkedHashMap(iA < 16 ? 16 : iA);
        Iterator it2 = arrayList.iterator();
        while (it2.hasNext()) {
            Object next = it2.next();
            linkedHashMap.put(Long.valueOf(((CardSideQuestionTypeRecommendation) next).a), next);
        }
        this.g = linkedHashMap;
        assistantMode.utils.h hVar = (assistantMode.utils.h) this.a;
        Set set2 = (Set) this.c;
        int iA2 = U.a(C.q(set2, 10));
        LinkedHashMap linkedHashMap2 = new LinkedHashMap(iA2 < 16 ? 16 : iA2);
        for (Object obj2 : set2) {
            assistantMode.enums.m mVar = (assistantMode.enums.m) obj2;
            LinkedHashSet linkedHashSetZ02 = CollectionsKt.z0((LinkedHashSet) this.f);
            assistantMode.enums.k kVar = assistantMode.enums.k.l;
            if (linkedHashSetZ02.contains(kVar) && !linkedHashSetZ02.contains(W4.b(kVar))) {
                linkedHashSetZ02.add(W4.b(kVar));
            }
            assistantMode.enums.k kVar2 = assistantMode.enums.k.d;
            boolean zContains = linkedHashSetZ02.contains(kVar2);
            assistantMode.utils.h hVar2 = (assistantMode.utils.h) this.a;
            if (zContains) {
                hVar2.getClass();
                if (!hVar2.i(s.g).isEmpty()) {
                    assistantMode.enums.k kVar3 = assistantMode.enums.k.m;
                    if (linkedHashSetZ02.contains(kVar3)) {
                        linkedHashSetZ02.add(kVar3);
                    }
                }
            }
            if (linkedHashSetZ02.contains(kVar2)) {
                hVar2.getClass();
                if (!hVar2.i(s.h).isEmpty()) {
                    assistantMode.enums.k kVar4 = assistantMode.enums.k.n;
                    if (linkedHashSetZ02.contains(kVar4)) {
                        linkedHashSetZ02.add(kVar4);
                    }
                }
            }
            if (mVar == assistantMode.enums.m.d) {
                androidx.credentials.playservices.controllers.BeginSignIn.c predicate = new androidx.credentials.playservices.controllers.BeginSignIn.c(this, 10);
                Intrinsics.checkNotNullParameter(linkedHashSetZ02, "<this>");
                Intrinsics.checkNotNullParameter(predicate, "predicate");
                G.x(linkedHashSetZ02, predicate, true);
            }
            linkedHashMap2.put(obj2, linkedHashSetZ02);
        }
        List list = hVar.a;
        int iA3 = U.a(C.q(list, 10));
        LinkedHashMap linkedHashMap3 = new LinkedHashMap(iA3 < 16 ? 16 : iA3);
        Iterator it3 = list.iterator();
        while (it3.hasNext()) {
            C1454a c1454a = (C1454a) it3.next();
            Long lValueOf = Long.valueOf(c1454a.a.a);
            Set setEntrySet = linkedHashMap2.entrySet();
            int iA4 = U.a(C.q(setEntrySet, i));
            LinkedHashMap linkedHashMap4 = new LinkedHashMap(iA4 < i2 ? i2 : iA4);
            Iterator it4 = setEntrySet.iterator();
            while (it4.hasNext()) {
                Map.Entry entry = (Map.Entry) it4.next();
                assistantMode.enums.m mVar2 = (assistantMode.enums.m) entry.getKey();
                Set set3 = (Set) entry.getValue();
                Set set4 = (Set) this.b;
                ArrayList arrayList2 = new ArrayList();
                for (Object obj3 : set4) {
                    if (((assistantMode.enums.m) obj3) != mVar2) {
                        arrayList2.add(obj3);
                    }
                }
                int iA5 = U.a(C.q(arrayList2, i));
                LinkedHashMap linkedHashMap5 = new LinkedHashMap(iA5 < 16 ? 16 : iA5);
                Iterator it5 = arrayList2.iterator();
                while (it5.hasNext()) {
                    Object next2 = it5.next();
                    assistantMode.enums.m mVar3 = (assistantMode.enums.m) next2;
                    ArrayList arrayList3 = new ArrayList();
                    for (Object obj4 : set3) {
                        Iterator it6 = it3;
                        LinkedHashMap linkedHashMap6 = linkedHashMap2;
                        assistantMode.enums.k kVar5 = (assistantMode.enums.k) obj4;
                        Iterator it7 = it4;
                        if ((mVar3 != assistantMode.enums.m.d || ((Set) this.d).contains(kVar5)) ? t(new C1457d(c1454a, mVar3, mVar2), hVar, kVar5) : false) {
                            arrayList3.add(obj4);
                        }
                        it3 = it6;
                        linkedHashMap2 = linkedHashMap6;
                        it4 = it7;
                    }
                    linkedHashMap5.put(next2, CollectionsKt.A0(arrayList3));
                }
                linkedHashMap4.put(mVar2, linkedHashMap5);
                i = 10;
            }
            linkedHashMap3.put(lValueOf, linkedHashMap4);
            i = 10;
            i2 = 16;
        }
        this.h = linkedHashMap3;
        ArrayList arrayList4 = new ArrayList();
        for (Map.Entry entry2 : linkedHashMap3.entrySet()) {
            long jLongValue = ((Number) entry2.getKey()).longValue();
            Map map = (Map) entry2.getValue();
            ArrayList arrayList5 = new ArrayList();
            for (Map.Entry entry3 : map.entrySet()) {
                assistantMode.enums.m mVar4 = (assistantMode.enums.m) entry3.getKey();
                Map map2 = (Map) entry3.getValue();
                ArrayList arrayList6 = new ArrayList();
                for (Map.Entry entry4 : map2.entrySet()) {
                    assistantMode.enums.m mVar5 = (assistantMode.enums.m) entry4.getKey();
                    Set set5 = (Set) entry4.getValue();
                    ArrayList arrayList7 = new ArrayList(C.q(set5, 10));
                    Iterator it8 = set5.iterator();
                    while (it8.hasNext()) {
                        arrayList7.add(new C1459f(jLongValue, mVar5, mVar4, (assistantMode.enums.k) it8.next()));
                    }
                    G.u(arrayList6, arrayList7);
                }
                G.u(arrayList5, arrayList6);
            }
            G.u(arrayList4, arrayList5);
        }
        this.i = CollectionsKt.A0(arrayList4);
        this.j = new LinkedHashMap();
    }

    public j(M m) {
        this.a = m;
        androidx.compose.runtime.collection.b bVar = new androidx.compose.runtime.collection.b(new C0836x0[16]);
        this.b = bVar;
        this.c = bVar;
        this.d = new androidx.compose.runtime.collection.b(new Object[16]);
        this.e = new androidx.compose.runtime.collection.b(new Function0[16]);
        this.g = new ArrayList();
        this.i = new C0222u();
        this.j = new C0222u();
    }

    /* JADX WARN: Illegal instructions before constructor call */
    public j(assistantMode.utils.h studyableMaterialDataSource, TestSettings testSettings) {
        Intrinsics.checkNotNullParameter(studyableMaterialDataSource, "studyableMaterialDataSource");
        Intrinsics.checkNotNullParameter(testSettings, "testSettings");
        List list = testSettings.a;
        Set setA0 = CollectionsKt.A0(list);
        Set setA02 = CollectionsKt.A0(testSettings.b);
        List list2 = testSettings.c;
        this(studyableMaterialDataSource, setA0, setA02, CollectionsKt.A0(list2), CollectionsKt.A0(list2), CollectionsKt.A0(list), null);
    }
}

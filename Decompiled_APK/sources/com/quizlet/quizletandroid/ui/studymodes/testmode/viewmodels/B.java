package com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels;

import androidx.compose.animation.d0;
import androidx.glance.appwidget.protobuf.Z;
import assistantMode.refactored.types.StudiableData;
import assistantMode.refactored.types.WrittenQuestion;
import assistantMode.types.AbstractC1458e;
import assistantMode.types.C1460g;
import assistantMode.types.TestGeneratorOutputMetadata;
import assistantMode.types.test.Test;
import assistantMode.types.test.TestSettings;
import com.google.android.gms.ads.internal.client.C1608n;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3133e5;
import com.google.android.gms.internal.mlkit_vision_barcode.M6;
import com.google.android.gms.internal.mlkit_vision_camera.O2;
import com.google.android.gms.internal.mlkit_vision_camera.Q2;
import com.google.android.gms.internal.mlkit_vision_camera.h3;
import com.quizlet.db.data.models.persisted.DBSession;
import com.quizlet.features.infra.studysetting.data.QuestionSettings;
import com.quizlet.features.infra.studysetting.data.TestStudyModeConfig;
import com.quizlet.generated.enums.E1;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import kotlin.Pair;
import kotlin.Unit;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;

/* loaded from: classes3.dex */
public final class B extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ G k;
    public final /* synthetic */ com.quizlet.features.infra.basestudy.data.models.dataproviders.a l;
    public final /* synthetic */ TestStudyModeConfig m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public B(G g, com.quizlet.features.infra.basestudy.data.models.dataproviders.a aVar, TestStudyModeConfig testStudyModeConfig, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = g;
        this.l = aVar;
        this.m = testStudyModeConfig;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new B(this.k, this.l, this.m, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((B) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws Throwable {
        Object objB;
        com.quizlet.quizletandroid.ui.studymodes.testmode.studyengine.c cVarC;
        com.quizlet.features.infra.studysetting.managers.a aVarG;
        Iterator it2;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        G g = this.k;
        if (i == 0) {
            Z.e(obj);
            com.quizlet.features.infra.basestudy.data.models.dataproviders.a aVar2 = this.l;
            ArrayList arrayList = aVar2.s;
            Intrinsics.checkNotNullExpressionValue(arrayList, "getTerms(...)");
            List listA = aVar2.a();
            Intrinsics.checkNotNullExpressionValue(listA, "getDiagramShapes(...)");
            List listB = aVar2.b();
            Intrinsics.checkNotNullExpressionValue(listB, "getImageRefs(...)");
            this.j = 1;
            objB = G.B(g, arrayList, listA, listB, this);
            if (objB == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
            objB = obj;
        }
        kotlin.v vVar = (kotlin.v) objB;
        StudiableData studiableData = (StudiableData) vVar.a;
        List list = (List) vVar.b;
        List list2 = (List) vVar.c;
        QuestionSettings questionSettingsE = g.E();
        TestStudyModeConfig testStudyModeConfig = this.m;
        TestSettings testSettings = com.quizlet.features.infra.basestudy.utils.b.h(testStudyModeConfig);
        QuestionSettings questionSettingsE2 = g.E();
        boolean z = g.H;
        com.quizlet.quizletandroid.ui.studymodes.testmode.studyengine.c cVar = g.d;
        if (!z || g.F) {
            g.F = false;
            cVarC = g.C(studiableData, list, list2, questionSettingsE.n, questionSettingsE2.o);
        } else {
            cVarC = cVar;
        }
        cVarC.getClass();
        Intrinsics.checkNotNullParameter(testSettings, "testSettings");
        C1608n c1608n = cVarC.a;
        if (c1608n == null) {
            Intrinsics.m("testGenerator");
            throw null;
        }
        Intrinsics.checkNotNullParameter(testSettings, "testSettings");
        h3.c(testSettings);
        assistantMode.utils.h hVar = (assistantMode.utils.h) c1608n.c;
        Collection collectionValues = new com.android.volley.m().d(testSettings, hVar, new androidx.compose.runtime.internal.j(hVar, testSettings)).values();
        if ((collectionValues instanceof Collection) && collectionValues.isEmpty()) {
            g.w.j(com.quizlet.quizletandroid.ui.studymodes.testmode.models.f.a);
        } else {
            Iterator it3 = collectionValues.iterator();
            while (it3.hasNext()) {
                if (!((List) it3.next()).isEmpty()) {
                    com.quizlet.features.infra.basestudy.manager.f fVar = g.D;
                    try {
                        aVarG = fVar.g();
                    } catch (NullPointerException unused) {
                        aVarG = null;
                    }
                    if (aVarG != null) {
                        List value = testStudyModeConfig.b;
                        Intrinsics.checkNotNullParameter(value, "value");
                        aVarG.n(E1.PROMPT_TERM_SIDES, M6.a(value));
                        List value2 = testStudyModeConfig.c;
                        Intrinsics.checkNotNullParameter(value2, "value");
                        aVarG.n(E1.ANSWER_TERM_SIDES, M6.a(value2));
                        aVarG.n(E1.TEST_QUESTION_COUNT, testStudyModeConfig.a);
                        HashSet questionTypes = testStudyModeConfig.d;
                        Intrinsics.checkNotNullParameter(questionTypes, "questionTypes");
                        Iterator it4 = questionTypes.iterator();
                        int i2 = 0;
                        while (it4.hasNext()) {
                            i2 |= ((com.quizlet.sharedconfig.study_setting_metadata.b) it4.next()).a;
                        }
                        aVarG.n(E1.TEST_QUESTION_TYPES, i2);
                        aVarG.m(E1.INSTANT_FEEDBACK, testStudyModeConfig.e);
                        aVarG.m(E1.FLEXIBLE_GRADING_ACCEPT_PARTIAL_ANSWERS, testStudyModeConfig.g);
                        aVarG.m(E1.SMART_GRADING, testStudyModeConfig.h);
                    }
                    TestSettings testSettings2 = com.quizlet.features.infra.basestudy.utils.b.h(testStudyModeConfig);
                    cVar.getClass();
                    Intrinsics.checkNotNullParameter(testSettings2, "testSettings");
                    C1608n c1608n2 = cVar.a;
                    if (c1608n2 == null) {
                        Intrinsics.m("testGenerator");
                        throw null;
                    }
                    Intrinsics.checkNotNullParameter(testSettings2, "testSettings");
                    c1608n2.getClass();
                    Intrinsics.checkNotNullParameter(testSettings2, "testSettings");
                    h3.c(testSettings2);
                    assistantMode.utils.h hVar2 = (assistantMode.utils.h) c1608n2.c;
                    LinkedHashMap configsByQuestionType = new com.android.volley.m().d(testSettings2, hVar2, new androidx.compose.runtime.internal.j(hVar2, testSettings2));
                    List listN0 = CollectionsKt.n0(configsByQuestionType.entrySet(), new test.utils.c(CollectionsKt.n0(testSettings2.a, new test.utils.c(kotlin.collections.B.j(assistantMode.enums.k.e, assistantMode.enums.k.d, assistantMode.enums.k.c, assistantMode.enums.k.b), 1)), 0));
                    Intrinsics.checkNotNullParameter(configsByQuestionType, "configsByQuestionType");
                    Collection collectionValues2 = configsByQuestionType.values();
                    ArrayList questionConfigs = new ArrayList();
                    Iterator it5 = collectionValues2.iterator();
                    while (it5.hasNext()) {
                        kotlin.collections.G.u(questionConfigs, (List) it5.next());
                    }
                    Intrinsics.checkNotNullParameter(questionConfigs, "questionConfigs");
                    Iterator it6 = questionConfigs.iterator();
                    while (it6.hasNext()) {
                        assistantMode.types.p pVar = (assistantMode.types.p) it6.next();
                        if (pVar instanceof AbstractC1458e) {
                            ((AbstractC1458e) pVar).a().size();
                        } else {
                            boolean z2 = pVar instanceof C1460g;
                        }
                    }
                    ArrayList arrayList2 = new ArrayList();
                    ArrayList arrayList3 = new ArrayList();
                    LinkedHashMap linkedHashMap = new LinkedHashMap();
                    ArrayList arrayList4 = new ArrayList();
                    Iterator it7 = listN0.iterator();
                    while (true) {
                        boolean z3 = false;
                        if (it7.hasNext()) {
                            Map.Entry entry = (Map.Entry) it7.next();
                            assistantMode.enums.k kVar = (assistantMode.enums.k) entry.getKey();
                            Iterator it8 = ((List) entry.getValue()).iterator();
                            while (it8.hasNext()) {
                                Q2 q2B = O2.b(kVar, (assistantMode.types.p) it8.next(), hVar2, z3);
                                assistantMode.refactored.types.d dVarD = q2B.d();
                                assistantMode.grading.d dVarC = q2B.c();
                                arrayList2.add(!(dVarD instanceof WrittenQuestion) ? dVarD : WrittenQuestion.b((WrittenQuestion) dVarD));
                                com.quizlet.features.infra.basestudy.manager.f fVar2 = fVar;
                                if (dVarD.a() != assistantMode.enums.k.c) {
                                    it2 = it7;
                                    arrayList3.add(dVarC);
                                } else {
                                    if (!(dVarC instanceof assistantMode.types.gradingContext.d)) {
                                        throw new IllegalArgumentException(("Error generating graders for MatchingQuestion answers. Expected MatchingQuestionGenerator, but got " + dVarC).toString());
                                    }
                                    int iB = q2B.b();
                                    int i3 = 0;
                                    while (i3 < iB) {
                                        arrayList3.add(new assistantMode.types.gradingContext.c((assistantMode.types.gradingContext.d) dVarC, i3));
                                        i3++;
                                        iB = iB;
                                        it7 = it7;
                                    }
                                    it2 = it7;
                                }
                                kotlin.collections.G.u(arrayList4, q2B.e());
                                if (test.utils.b.a.contains(dVarD.a())) {
                                    Long l = dVarD.getMetadata().a;
                                    if (l == null) {
                                        throw new Error("Question does not have a studiable item id for checkpoint questions");
                                    }
                                    linkedHashMap.put(l, dVarC.c());
                                }
                                fVar = fVar2;
                                it7 = it2;
                                z3 = false;
                            }
                        } else {
                            com.quizlet.features.infra.basestudy.manager.f fVar3 = fVar;
                            if (arrayList4.size() != arrayList3.size()) {
                                throw new IllegalArgumentException(d0.p("Could not generate test, expected equal numbers of studiableItemIds and graders, but got ", arrayList4.size(), " and ", arrayList3.size()).toString());
                            }
                            ArrayList arrayListC0 = CollectionsKt.C0(arrayList4, arrayList3);
                            ArrayList arrayList5 = new ArrayList(kotlin.collections.C.q(arrayListC0, 10));
                            Iterator it9 = arrayListC0.iterator();
                            while (it9.hasNext()) {
                                Pair pair = (Pair) it9.next();
                                arrayList5.add(new test.utils.a((Long) pair.a, (assistantMode.grading.d) pair.b));
                            }
                            c1608n2.b = arrayList5;
                            assistantMode.types.test.a aVarT = ((metering.manager.a) c1608n2.e).T(new Test(arrayList2, new TestGeneratorOutputMetadata(false, 7)));
                            if (!(aVarT instanceof assistantMode.types.test.b)) {
                                throw new IllegalStateException(("Expected output type " + K.a(assistantMode.types.test.b.class) + ", but got " + K.a(aVarT.getClass())).toString());
                            }
                            List list3 = ((Test) ((assistantMode.types.test.b) aVarT)).a;
                            int size = list3.size();
                            ArrayList arrayList6 = new ArrayList(size);
                            for (int i4 = 0; i4 < size; i4++) {
                                arrayList6.add(null);
                            }
                            cVar.e = arrayList6;
                            List diagramShapes = cVar.b;
                            if (diagramShapes == null) {
                                Intrinsics.m("diagramShapes");
                                throw null;
                            }
                            List images = cVar.c;
                            if (images == null) {
                                Intrinsics.m("images");
                                throw null;
                            }
                            Intrinsics.checkNotNullParameter(list3, "<this>");
                            Intrinsics.checkNotNullParameter(diagramShapes, "diagramShapes");
                            Intrinsics.checkNotNullParameter(images, "images");
                            ArrayList newQuestions = new ArrayList(kotlin.collections.C.q(list3, 10));
                            Iterator it10 = list3.iterator();
                            while (it10.hasNext()) {
                                newQuestions.add(AbstractC3133e5.c((assistantMode.refactored.types.d) it10.next(), diagramShapes, images));
                            }
                            com.quizlet.quizletandroid.ui.studymodes.testmode.studyengine.e eVar = g.e;
                            eVar.getClass();
                            Intrinsics.checkNotNullParameter(newQuestions, "newQuestions");
                            ArrayList arrayList7 = eVar.a;
                            arrayList7.clear();
                            arrayList7.addAll(newQuestions);
                            g.G = true;
                            DBSession dBSessionB = fVar3.b();
                            g.K = dBSessionB;
                            g.x.j(new com.quizlet.quizletandroid.ui.studymodes.testmode.models.w(dBSessionB.getId()));
                            g.J(0);
                        }
                    }
                }
            }
            g.w.j(com.quizlet.quizletandroid.ui.studymodes.testmode.models.f.a);
        }
        return Unit.a;
    }
}

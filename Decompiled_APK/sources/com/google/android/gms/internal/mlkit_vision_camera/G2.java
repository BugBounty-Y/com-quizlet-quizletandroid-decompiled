package com.google.android.gms.internal.mlkit_vision_camera;

import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import assistantMode.types.C1454a;
import assistantMode.types.aliases.ExperimentConfiguration;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.google.android.gms.internal.mlkit_vision_barcode.X4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3586b5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.W4;
import com.quizlet.assembly.compose.buttons.C4076a;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Set;
import kotlin.NoWhenBranchMatchedException;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;
import org.koin.core.error.DefinitionOverrideException;
import org.koin.core.error.KoinAppAlreadyStartedException;

/* loaded from: classes2.dex */
public abstract class G2 {
    public static final void a(com.quizlet.features.questiontypes.composables.d primaryContinueState, androidx.compose.ui.q qVar, com.quizlet.features.questiontypes.composables.d dVar, InterfaceC0806l interfaceC0806l, int i, int i2) {
        com.quizlet.features.questiontypes.composables.d dVar2;
        int i3;
        com.quizlet.features.questiontypes.composables.d dVar3;
        Intrinsics.checkNotNullParameter(primaryContinueState, "primaryContinueState");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(941884434);
        int i4 = i | (c0814p.f(primaryContinueState) ? 4 : 2) | (c0814p.f(qVar) ? 32 : 16);
        int i5 = i2 & 4;
        if (i5 != 0) {
            i3 = i4 | 384;
            dVar2 = dVar;
        } else {
            dVar2 = dVar;
            i3 = i4 | (c0814p.f(dVar2) ? 256 : 128);
        }
        if ((i3 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
            dVar3 = dVar2;
        } else {
            com.quizlet.features.questiontypes.composables.d dVar4 = i5 != 0 ? null : dVar2;
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.s();
            androidx.compose.ui.q qVarU = AbstractC0382e.u(qVar, com.quizlet.ui.resources.designsystem.generated.j.h);
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p, 0);
            int i6 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVarU);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, bA, C0914j.f);
            C0776c.E(c0814p, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i6))) {
                android.support.v4.media.session.a.z(i6, c0814p, i6, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            androidx.compose.ui.q qVarC2 = androidx.compose.foundation.layout.K0.c(nVar, 1.0f);
            mVar.u();
            W4.a(AbstractC3106b5.d(c0814p, primaryContinueState.a), AbstractC0382e.y(qVarC2, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.g, 7), primaryContinueState.b, false, null, null, null, null, null, false, c0814p, 0, 1016);
            c0814p = c0814p;
            c0814p.X(-598226412);
            if (dVar4 != null) {
                AbstractC3586b5.a(AbstractC3106b5.d(c0814p, dVar4.a), androidx.compose.foundation.layout.K0.c(nVar, 1.0f), dVar4.b, false, C4076a.l, null, null, null, null, c0814p, 48, 1000);
            }
            c0814p.p(false);
            c0814p.p(true);
            dVar3 = dVar4;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.navigation.compose.u(i, i2, 28, primaryContinueState, qVar, dVar3);
        }
    }

    public static final assistantMode.enums.C b(assistantMode.enums.w studyPathGoal, assistantMode.enums.y knowledgeLevel) {
        Intrinsics.checkNotNullParameter(studyPathGoal, "studyPathGoal");
        Intrinsics.checkNotNullParameter(knowledgeLevel, "knowledgeLevel");
        int iOrdinal = studyPathGoal.ordinal();
        if (iOrdinal == 1) {
            int iOrdinal2 = knowledgeLevel.ordinal();
            if (iOrdinal2 != 0 && iOrdinal2 != 1) {
                if (iOrdinal2 == 2) {
                    return assistantMode.enums.C.e;
                }
                if (iOrdinal2 != 3) {
                    throw new NoWhenBranchMatchedException();
                }
            }
            return assistantMode.enums.C.d;
        }
        if (iOrdinal != 2 && iOrdinal != 3) {
            throw new IllegalArgumentException("StudyPathGoal: " + studyPathGoal + " is not supported");
        }
        int iOrdinal3 = knowledgeLevel.ordinal();
        if (iOrdinal3 != 0 && iOrdinal3 != 1) {
            if (iOrdinal3 == 2) {
                return assistantMode.enums.C.c;
            }
            if (iOrdinal3 != 3) {
                throw new NoWhenBranchMatchedException();
            }
        }
        return assistantMode.enums.C.b;
    }

    public static final List c(assistantMode.utils.h studyableMaterialDataSource, assistantMode.enums.w wVar, assistantMode.enums.y yVar, ExperimentConfiguration experimentConfiguration) throws DefinitionOverrideException, KoinAppAlreadyStartedException {
        boolean z;
        List listJ;
        com.airbnb.lottie.parser.l lVarD;
        assistantMode.enums.m mVar;
        assistantMode.enums.m mVar2;
        Intrinsics.checkNotNullParameter(studyableMaterialDataSource, "studyableMaterialDataSource");
        H2.e(experimentConfiguration);
        LinkedHashMap idsWithContentByCardSide = V2.b(studyableMaterialDataSource.a);
        List cards = studyableMaterialDataSource.a;
        Intrinsics.checkNotNullParameter(cards, "cards");
        List list = assistantMode.a.b;
        int iA = kotlin.collections.U.a(kotlin.collections.C.q(list, 10));
        if (iA < 16) {
            iA = 16;
        }
        LinkedHashMap linkedHashMap = new LinkedHashMap(iA);
        for (Object obj : list) {
            assistantMode.enums.m cardSide = (assistantMode.enums.m) obj;
            ArrayList arrayList = new ArrayList();
            for (Object obj2 : cards) {
                C1454a c1454a = (C1454a) obj2;
                c1454a.getClass();
                Intrinsics.checkNotNullParameter(cardSide, "cardSide");
                if (c1454a.a(cardSide)) {
                    Intrinsics.checkNotNullParameter(cardSide, "cardSide");
                    if (StringsKt.g0(k3.g(c1454a.i(cardSide).e())).toString().length() < 60) {
                        arrayList.add(obj2);
                    }
                }
            }
            ArrayList arrayList2 = new ArrayList(kotlin.collections.C.q(arrayList, 10));
            Iterator it2 = arrayList.iterator();
            while (it2.hasNext()) {
                arrayList2.add(Long.valueOf(((C1454a) it2.next()).a.a));
            }
            linkedHashMap.put(obj, CollectionsKt.A0(arrayList2));
        }
        List list2 = studyableMaterialDataSource.a;
        ArrayList arrayList3 = new ArrayList(kotlin.collections.C.q(list2, 10));
        Iterator it3 = list2.iterator();
        while (it3.hasNext()) {
            arrayList3.add(Long.valueOf(((C1454a) it3.next()).a.a));
        }
        Set setA0 = CollectionsKt.A0(arrayList3);
        List listI = studyableMaterialDataSource.i(assistantMode.enums.s.c);
        ArrayList arrayList4 = new ArrayList(kotlin.collections.C.q(listI, 10));
        Iterator it4 = listI.iterator();
        while (it4.hasNext()) {
            arrayList4.add(Long.valueOf(((assistantMode.refactored.types.f) it4.next()).b()));
        }
        boolean zIsEmpty = CollectionsKt.Q(setA0, CollectionsKt.A0(arrayList4)).isEmpty();
        List list3 = studyableMaterialDataSource.a;
        if (list3 == null || !list3.isEmpty()) {
            Iterator it5 = list3.iterator();
            while (it5.hasNext()) {
                if (((C1454a) it5.next()).i != null) {
                    z = true;
                    break;
                }
            }
            z = false;
        } else {
            z = false;
        }
        boolean zIsEmpty2 = studyableMaterialDataSource.i(assistantMode.enums.s.h).isEmpty();
        boolean zIsEmpty3 = studyableMaterialDataSource.i(assistantMode.enums.s.g).isEmpty();
        if (z) {
            kmppUtils.bitmasks.a[] aVarArr = (kmppUtils.bitmasks.a[]) kotlin.collections.A.b(assistantMode.enums.k.d).toArray(new assistantMode.enums.k[0]);
            lVarD = n3.d((kmppUtils.bitmasks.a[]) Arrays.copyOf(aVarArr, aVarArr.length));
        } else {
            if (wVar == null) {
                throw new IllegalStateException("StudyPathGoal is null");
            }
            if (yVar == null) {
                throw new IllegalStateException("StudyPathKnowledgeLevel is null");
            }
            int iOrdinal = wVar.ordinal();
            if (iOrdinal == 1) {
                int iOrdinal2 = yVar.ordinal();
                if (iOrdinal2 == 0 || iOrdinal2 == 1) {
                    listJ = kotlin.collections.B.j(assistantMode.enums.k.d, assistantMode.enums.k.f);
                } else if (iOrdinal2 != 2) {
                    if (iOrdinal2 != 3) {
                        throw new NoWhenBranchMatchedException();
                    }
                    listJ = kotlin.collections.B.j(assistantMode.enums.k.d, assistantMode.enums.k.f);
                } else {
                    listJ = kotlin.collections.A.b(assistantMode.enums.k.b);
                }
            } else {
                if (iOrdinal != 2 && iOrdinal != 3) {
                    throw new IllegalArgumentException("StudyPathGoal " + wVar + " is not supported in RecommendDefaultConfiguration.getEnabledQuestionTypes");
                }
                int iOrdinal3 = yVar.ordinal();
                if (iOrdinal3 == 0 || iOrdinal3 == 1) {
                    listJ = kotlin.collections.B.j(assistantMode.enums.k.d, assistantMode.enums.k.b);
                } else if (iOrdinal3 != 2) {
                    if (iOrdinal3 != 3) {
                        throw new NoWhenBranchMatchedException();
                    }
                    listJ = kotlin.collections.B.j(assistantMode.enums.k.d, assistantMode.enums.k.b);
                } else {
                    listJ = kotlin.collections.B.j(assistantMode.enums.k.f, assistantMode.enums.k.b);
                }
            }
            ArrayList arrayListY0 = CollectionsKt.y0(listJ);
            assistantMode.enums.m[] mVarArr = {assistantMode.enums.m.b, assistantMode.enums.m.c};
            ArrayList arrayList5 = new ArrayList();
            int i = 0;
            while (i < 2) {
                assistantMode.enums.m termSide = mVarArr[i];
                Set set = (Set) linkedHashMap.get(termSide);
                if (set == null) {
                    throw new Error("Missing " + termSide + " in reasonablyTypableIdsByCardSide");
                }
                Set set2 = (Set) idsWithContentByCardSide.get(termSide);
                if (set2 == null) {
                    throw new Error("Missing " + termSide + " in idsWithContentByCardSide");
                }
                Intrinsics.checkNotNullParameter(termSide, "termSide");
                int iOrdinal4 = termSide.ordinal();
                boolean z2 = zIsEmpty3;
                if (iOrdinal4 == 0) {
                    mVar = assistantMode.enums.m.c;
                } else {
                    if (iOrdinal4 != 1) {
                        throw new IllegalStateException("Card side is not a text side");
                    }
                    mVar = assistantMode.enums.m.b;
                }
                Set set3 = (Set) idsWithContentByCardSide.get(mVar);
                if (set3 == null) {
                    Intrinsics.checkNotNullParameter(termSide, "termSide");
                    int iOrdinal5 = termSide.ordinal();
                    if (iOrdinal5 == 0) {
                        mVar2 = assistantMode.enums.m.c;
                    } else {
                        if (iOrdinal5 != 1) {
                            throw new IllegalStateException("Card side is not a text side");
                        }
                        mVar2 = assistantMode.enums.m.b;
                    }
                    throw new Error("Missing " + mVar2 + " in otherTextSideIdsWithContent");
                }
                Set set4 = set2;
                if (!(set4 instanceof Collection) || !set4.isEmpty()) {
                    Iterator it6 = set4.iterator();
                    while (true) {
                        if (it6.hasNext()) {
                            long jLongValue = ((Number) it6.next()).longValue();
                            if (!set.contains(Long.valueOf(jLongValue)) && set3.contains(Long.valueOf(jLongValue))) {
                                arrayList5.add(termSide);
                                break;
                            }
                        }
                    }
                }
                i++;
                zIsEmpty3 = z2;
            }
            boolean z3 = zIsEmpty3;
            if (!arrayList5.isEmpty()) {
                arrayListY0.add(assistantMode.enums.k.f);
            }
            if (zIsEmpty) {
                arrayListY0.remove(assistantMode.enums.k.l);
            } else {
                arrayListY0.add(assistantMode.enums.k.l);
            }
            if (!zIsEmpty2) {
                arrayListY0.add(assistantMode.enums.k.n);
            }
            if (!z3) {
                arrayListY0.add(assistantMode.enums.k.m);
            }
            kmppUtils.bitmasks.a[] aVarArr2 = (kmppUtils.bitmasks.a[]) arrayListY0.toArray(new assistantMode.enums.k[0]);
            lVarD = n3.d((kmppUtils.bitmasks.a[]) Arrays.copyOf(aVarArr2, aVarArr2.length));
        }
        List listB = W2.b(idsWithContentByCardSide);
        ArrayList arrayList6 = new ArrayList(kotlin.collections.C.q(listB, 10));
        Iterator it7 = listB.iterator();
        while (it7.hasNext()) {
            arrayList6.add(X4.c((assistantMode.enums.m) it7.next()));
        }
        kmppUtils.bitmasks.a[] aVarArr3 = (kmppUtils.bitmasks.a[]) arrayList6.toArray(new assistantMode.enums.E[0]);
        com.airbnb.lottie.parser.l lVarD2 = n3.d((kmppUtils.bitmasks.a[]) Arrays.copyOf(aVarArr3, aVarArr3.length));
        Intrinsics.checkNotNullParameter(idsWithContentByCardSide, "idsWithContentByCardSide");
        ArrayList arrayListK = kotlin.collections.B.k(assistantMode.enums.m.c, assistantMode.enums.m.b);
        assistantMode.enums.m mVar3 = assistantMode.enums.m.d;
        Object obj3 = idsWithContentByCardSide.get(mVar3);
        if (obj3 == null) {
            throw new IllegalStateException("Missing LOCATION in idsWithContentByTermSide");
        }
        if (!((Set) obj3).isEmpty()) {
            arrayListK.add(mVar3);
        }
        List listG = CollectionsKt.G(arrayListK);
        ArrayList arrayList7 = new ArrayList(kotlin.collections.C.q(listG, 10));
        Iterator it8 = listG.iterator();
        while (it8.hasNext()) {
            arrayList7.add(X4.c((assistantMode.enums.m) it8.next()));
        }
        kmppUtils.bitmasks.a[] aVarArr4 = (kmppUtils.bitmasks.a[]) arrayList7.toArray(new assistantMode.enums.E[0]);
        return kotlin.collections.B.j(new assistantMode.types.s(assistantMode.enums.z.l, lVarD2.b), new assistantMode.types.s(assistantMode.enums.z.m, n3.d((kmppUtils.bitmasks.a[]) Arrays.copyOf(aVarArr4, aVarArr4.length)).b), new assistantMode.types.r(assistantMode.enums.z.j), new assistantMode.types.r(assistantMode.enums.z.k), new assistantMode.types.s(assistantMode.enums.z.i, lVarD.b));
    }
}

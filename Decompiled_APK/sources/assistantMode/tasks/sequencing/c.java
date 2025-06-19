package assistantMode.tasks.sequencing;

import androidx.compose.runtime.internal.j;
import assistantMode.enums.k;
import assistantMode.enums.m;
import assistantMode.types.C1455b;
import assistantMode.types.C1456c;
import assistantMode.types.C1459f;
import assistantMode.types.w;
import assistantMode.utils.g;
import com.google.android.gms.internal.mlkit_vision_barcode.W4;
import com.google.android.gms.internal.mlkit_vision_camera.K2;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import kotlin.Pair;
import kotlin.collections.A;
import kotlin.collections.C;
import kotlin.collections.CollectionsKt;
import kotlin.collections.K;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public final class c implements d {

    @NotNull
    public static final b Companion = new b();
    public final androidx.collection.internal.b a;
    public final j b;
    public final k c;

    public c(androidx.collection.internal.b cardKnowledgeTracker, j questionTypeApplicability, k questionType) {
        Intrinsics.checkNotNullParameter(cardKnowledgeTracker, "cardKnowledgeTracker");
        Intrinsics.checkNotNullParameter(questionTypeApplicability, "questionTypeApplicability");
        Intrinsics.checkNotNullParameter(questionType, "questionType");
        this.a = cardKnowledgeTracker;
        this.b = questionTypeApplicability;
        this.c = questionType;
    }

    @Override // assistantMode.tasks.sequencing.d
    public final void f(List completedStudiableItemTuples) {
        Intrinsics.checkNotNullParameter(completedStudiableItemTuples, "completedStudiableItemTuples");
    }

    @Override // assistantMode.tasks.sequencing.d
    public final w g() {
        Object obj;
        j jVar = this.b;
        Set setE = jVar.e();
        ArrayList arrayList = new ArrayList();
        Iterator it2 = setE.iterator();
        while (it2.hasNext()) {
            long jLongValue = ((Number) it2.next()).longValue();
            Iterator it3 = jVar.h(jLongValue, W4.d(this.c, jVar.i(jLongValue), true)).iterator();
            if (it3.hasNext()) {
                Object next = it3.next();
                if (it3.hasNext()) {
                    C1459f c1459f = (C1459f) next;
                    int iF = jVar.f(c1459f.a, c1459f.d, c1459f.c);
                    do {
                        Object next2 = it3.next();
                        C1459f c1459f2 = (C1459f) next2;
                        int iF2 = jVar.f(c1459f2.a, c1459f2.d, c1459f2.c);
                        if (iF > iF2) {
                            next = next2;
                            iF = iF2;
                        }
                    } while (it3.hasNext());
                }
                obj = next;
            } else {
                obj = null;
            }
            C1459f c1459f3 = (C1459f) obj;
            if (c1459f3 != null) {
                arrayList.add(c1459f3);
            }
        }
        int i = 10;
        ArrayList arrayList2 = new ArrayList(C.q(arrayList, 10));
        Iterator it4 = arrayList.iterator();
        while (it4.hasNext()) {
            C1459f questionSpec = (C1459f) it4.next();
            androidx.collection.internal.b bVar = this.a;
            bVar.getClass();
            Intrinsics.checkNotNullParameter(questionSpec, "questionSpec");
            Iterable allAnswersForCard = (List) bVar.a.get(Long.valueOf(questionSpec.a));
            if (allAnswersForCard == null) {
                allAnswersForCard = K.a;
            }
            long jCurrentTimeMillis = System.currentTimeMillis();
            Intrinsics.checkNotNullParameter(allAnswersForCard, "allAnswersForCard");
            m answerSide = questionSpec.c;
            Intrinsics.checkNotNullParameter(answerSide, "answerSide");
            k proposedQuestionType = questionSpec.d;
            Intrinsics.checkNotNullParameter(proposedQuestionType, "proposedQuestionType");
            ArrayList arrayList3 = new ArrayList();
            for (Object obj2 : allAnswersForCard) {
                C1455b c1455b = (C1455b) obj2;
                if (c1455b.b == answerSide || c1455b.c == answerSide) {
                    arrayList3.add(obj2);
                }
            }
            List<C1455b> listN0 = CollectionsKt.n0(arrayList3, g.a);
            ArrayList arrayList4 = new ArrayList(C.q(listN0, i));
            for (C1455b c1455b2 : listN0) {
                arrayList4.add(new C1456c(Boolean.valueOf(c1455b2.a), c1455b2.c, c1455b2.d, c1455b2.e, c1455b2.f, Boolean.FALSE, K2.c(c1455b2.f, listN0)));
                it4 = it4;
                arrayList2 = arrayList2;
            }
            ArrayList arrayList5 = arrayList2;
            Iterator it5 = it4;
            ArrayList answerFeatures = CollectionsKt.d0(arrayList4, new C1456c(null, answerSide, proposedQuestionType, questionSpec.a, jCurrentTimeMillis, null, K2.c(jCurrentTimeMillis, listN0)));
            Object obj3 = assistantMode.learningModel.a.a;
            Intrinsics.checkNotNullParameter(answerFeatures, "answerFeatures");
            Double d = assistantMode.learningModel.a.c(answerFeatures).b;
            if (d == null) {
                throw new IllegalStateException("recursiveComputeScore did not return a score");
            }
            double dDoubleValue = d.doubleValue();
            if (Double.isNaN(dDoubleValue)) {
                throw new IllegalStateException("recursiveComputeScore returned NaN");
            }
            arrayList5.add(new Pair(questionSpec, Double.valueOf(dDoubleValue <= 0.8d ? (dDoubleValue * 1.25d) + ((-0.78125d) * dDoubleValue * dDoubleValue) + 0.5d : ((40 * dDoubleValue) + (((-25) * dDoubleValue) * dDoubleValue)) - 15)));
            arrayList2 = arrayList5;
            it4 = it5;
            i = 10;
        }
        List listN02 = CollectionsKt.n0(arrayList2, new androidx.constraintlayout.core.e(15));
        ArrayList arrayList6 = new ArrayList(C.q(listN02, 10));
        Iterator it6 = listN02.iterator();
        while (it6.hasNext()) {
            arrayList6.add((C1459f) ((Pair) it6.next()).a);
        }
        List listC = A.c(CollectionsKt.p0(arrayList6, 7));
        ArrayList arrayList7 = new ArrayList(C.q(listC, 10));
        Iterator it7 = ((ArrayList) listC).iterator();
        while (it7.hasNext()) {
            arrayList7.add(((C1459f) it7.next()).d);
        }
        return new w(arrayList7, listC);
    }
}

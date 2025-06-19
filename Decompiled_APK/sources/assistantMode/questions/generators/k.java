package assistantMode.questions.generators;

import assistantMode.grading.o;
import assistantMode.refactored.types.SeparatedOptionMatchingQuestion;
import assistantMode.types.C1454a;
import assistantMode.types.QuestionElement;
import assistantMode.types.QuestionMetadata;
import assistantMode.types.gradingContext.ExpectedMatchQuestionPair;
import assistantMode.types.n;
import com.google.android.gms.internal.mlkit_vision_camera.N2;
import com.google.android.gms.internal.mlkit_vision_camera.Q2;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import kotlin.collections.B;
import kotlin.collections.C;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;
import kotlin.m;
import kotlin.ranges.IntRange;

/* loaded from: classes.dex */
public final class k extends Q2 {
    public final n a;
    public final Object b;
    public final ArrayList c;
    public final List d;
    public final ArrayList e;
    public final ArrayList f;
    public final ArrayList g;
    public final SeparatedOptionMatchingQuestion h;

    public k(n questionConfig) {
        Intrinsics.checkNotNullParameter(questionConfig, "questionConfig");
        assistantMode.enums.k questionType = assistantMode.enums.k.c;
        Intrinsics.checkNotNullParameter(questionType, "questionType");
        this.a = questionConfig;
        kotlin.k kVarA = kotlin.l.a(m.a, new o(0, 3));
        this.b = kVarA;
        ArrayList arrayListD = N2.d(questionConfig.b, CollectionsKt.w0(questionConfig.a));
        this.c = arrayListD;
        this.d = B.n(B.h(questionConfig.a), (kotlin.random.e) kVarA.getValue());
        IntRange intRangeH = B.h(arrayListD);
        ArrayList arrayList = new ArrayList(C.q(intRangeH, 10));
        kotlin.ranges.i it2 = intRangeH.iterator();
        while (it2.c) {
            arrayList.add(Integer.valueOf(this.d.indexOf(Integer.valueOf(it2.nextInt()))));
        }
        this.e = arrayList;
        ArrayList arrayListF = f(this.d);
        this.f = arrayListF;
        this.g = f(CollectionsKt.w0(B.h(this.c)));
        ArrayList arrayList2 = this.c;
        n nVar = this.a;
        this.h = new SeparatedOptionMatchingQuestion(arrayList2, arrayListF, new QuestionMetadata(null, nVar.b, nVar.c, null, null, null, 248));
    }

    @Override // com.google.android.gms.internal.mlkit_vision_camera.Q2
    public final int b() {
        return this.c.size();
    }

    @Override // com.google.android.gms.internal.mlkit_vision_camera.Q2
    public final assistantMode.grading.d c() {
        ArrayList arrayList = new ArrayList();
        Iterator it2 = this.c.iterator();
        int i = 0;
        while (it2.hasNext()) {
            Object next = it2.next();
            int i2 = i + 1;
            if (i < 0) {
                B.p();
                throw null;
            }
            QuestionElement questionElement = (QuestionElement) next;
            Iterator it3 = this.f.iterator();
            int i3 = 0;
            while (it3.hasNext()) {
                Object next2 = it3.next();
                int i4 = i3 + 1;
                if (i3 < 0) {
                    B.p();
                    throw null;
                }
                QuestionElement questionElement2 = (QuestionElement) next2;
                n nVar = this.a;
                List list = nVar.a;
                ArrayList arrayList2 = new ArrayList();
                for (Object obj : list) {
                    C1454a c1454a = (C1454a) obj;
                    QuestionElement questionElementC = N2.c(c1454a, nVar.b);
                    Iterator it4 = it2;
                    QuestionElement questionElementC2 = N2.c(c1454a, nVar.c);
                    if (Intrinsics.b(questionElement, questionElementC) && Intrinsics.b(questionElement2, questionElementC2)) {
                        arrayList2.add(obj);
                    }
                    it2 = it4;
                }
                Iterator it5 = it2;
                if (arrayList2.size() > 0) {
                    arrayList.add(new ExpectedMatchQuestionPair(i, i3));
                }
                i3 = i4;
                it2 = it5;
            }
            i = i2;
        }
        return new assistantMode.types.gradingContext.d(CollectionsKt.w0(this.g), this.e, arrayList);
    }

    @Override // com.google.android.gms.internal.mlkit_vision_camera.Q2
    public final assistantMode.refactored.types.d d() {
        return this.h;
    }

    @Override // com.google.android.gms.internal.mlkit_vision_camera.Q2
    public final List e() {
        List list = this.a.a;
        ArrayList arrayList = new ArrayList(C.q(list, 10));
        Iterator it2 = list.iterator();
        while (it2.hasNext()) {
            arrayList.add(Long.valueOf(((C1454a) it2.next()).a.a));
        }
        return arrayList;
    }

    public final ArrayList f(List list) {
        ArrayList arrayList = new ArrayList(C.q(list, 10));
        Iterator it2 = list.iterator();
        while (it2.hasNext()) {
            int iIntValue = ((Number) it2.next()).intValue();
            n nVar = this.a;
            arrayList.add(N2.c((C1454a) nVar.a.get(iIntValue), nVar.c));
        }
        return arrayList;
    }
}

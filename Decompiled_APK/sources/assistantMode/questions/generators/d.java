package assistantMode.questions.generators;

import assistantMode.refactored.types.MultipleChoiceQuestion;
import assistantMode.types.B;
import assistantMode.types.C1454a;
import assistantMode.types.QuestionElement;
import com.google.android.gms.internal.mlkit_vision_camera.N2;
import com.google.android.gms.internal.mlkit_vision_camera.Q2;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import kotlin.collections.C;
import kotlin.collections.CollectionsKt;
import kotlin.collections.Z;

/* loaded from: classes.dex */
public final class d extends Q2 {
    public final B a;
    public final Object b;
    public final int c;
    public final int d;
    public final QuestionElement e;
    public final long f;
    public final MultipleChoiceQuestion g;
    public final int h;

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:102:0x02d9  */
    /* JADX WARN: Removed duplicated region for block: B:172:0x049e A[EDGE_INSN: B:217:0x049e->B:172:0x049e BREAK  A[LOOP:13: B:152:0x0447->B:219:?], EDGE_INSN: B:172:0x049e->B:173:0x049f BREAK  A[LOOP:14: B:160:0x0462->B:222:?]] */
    /* JADX WARN: Removed duplicated region for block: B:176:0x04cd A[LOOP:16: B:174:0x04c7->B:176:0x04cd, LOOP_END] */
    /* JADX WARN: Removed duplicated region for block: B:180:0x04ee A[LOOP:17: B:178:0x04e8->B:180:0x04ee, LOOP_END] */
    /* JADX WARN: Removed duplicated region for block: B:192:0x052d  */
    /* JADX WARN: Removed duplicated region for block: B:69:0x019e  */
    /* JADX WARN: Type inference failed for: r13v8, types: [java.util.ArrayList] */
    /* JADX WARN: Type inference failed for: r1v10, types: [java.lang.Object, kotlin.k] */
    /* JADX WARN: Type inference failed for: r1v19, types: [java.lang.Object, kotlin.k] */
    /* JADX WARN: Type inference failed for: r1v34, types: [java.lang.Object, kotlin.k] */
    /* JADX WARN: Type inference failed for: r2v41, types: [java.lang.Object, kotlin.k] */
    /* JADX WARN: Type inference failed for: r3v14, types: [java.util.Collection] */
    /* JADX WARN: Type inference failed for: r3v15, types: [java.lang.Iterable] */
    /* JADX WARN: Type inference failed for: r3v18, types: [java.lang.Object, kotlin.k] */
    /* JADX WARN: Type inference failed for: r3v78, types: [kotlin.collections.K] */
    /* JADX WARN: Type inference failed for: r3v81, types: [java.util.ArrayList] */
    /* JADX WARN: Type inference failed for: r3v90 */
    /* JADX WARN: Type inference failed for: r3v91 */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public d(assistantMode.types.B r19, assistantMode.utils.h r20, boolean r21) {
        /*
            Method dump skipped, instructions count: 1406
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: assistantMode.questions.generators.d.<init>(assistantMode.types.B, assistantMode.utils.h, boolean):void");
    }

    @Override // com.google.android.gms.internal.mlkit_vision_camera.Q2
    public final assistantMode.grading.d c() {
        Set setB = Z.b(Integer.valueOf(this.h));
        B b = this.a;
        return new assistantMode.types.gradingContext.e(setB, N2.c((C1454a) CollectionsKt.L(b.a()), b.a.c), null);
    }

    @Override // com.google.android.gms.internal.mlkit_vision_camera.Q2
    public final assistantMode.refactored.types.d d() {
        return this.g;
    }

    @Override // com.google.android.gms.internal.mlkit_vision_camera.Q2
    public final List e() {
        List listA = this.a.a();
        ArrayList arrayList = new ArrayList(C.q(listA, 10));
        Iterator it2 = listA.iterator();
        while (it2.hasNext()) {
            arrayList.add(Long.valueOf(((C1454a) it2.next()).a.a));
        }
        return arrayList;
    }
}

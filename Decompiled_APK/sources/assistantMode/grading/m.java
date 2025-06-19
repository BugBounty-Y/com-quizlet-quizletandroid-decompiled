package assistantMode.grading;

import assistantMode.types.BooleanAnswer;
import assistantMode.types.QuestionElement;
import assistantMode.types.v;
import com.google.android.gms.internal.mlkit_vision_camera.J2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class m implements d {
    public final boolean a;
    public final QuestionElement b;

    public m(boolean z, QuestionElement expectedAnswerDescription) {
        Intrinsics.checkNotNullParameter(expectedAnswerDescription, "expectedAnswerDescription");
        this.a = z;
        this.b = expectedAnswerDescription;
    }

    /* JADX WARN: Removed duplicated region for block: B:14:0x001c  */
    @Override // assistantMode.grading.d
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object a(assistantMode.types.v r7, com.google.android.gms.internal.mlkit_vision_camera.J2 r8, kotlin.coroutines.jvm.internal.c r9) {
        /*
            r6 = this;
            r9 = 1
            if (r7 != 0) goto L5
            r0 = r9
            goto L7
        L5:
            boolean r0 = r7 instanceof assistantMode.types.BooleanAnswer
        L7:
            if (r0 == 0) goto L4e
            boolean r0 = r8 instanceof assistantMode.grading.f
            if (r0 == 0) goto L36
            assistantMode.types.GradedAnswer r8 = new assistantMode.types.GradedAnswer
            r0 = r7
            assistantMode.types.BooleanAnswer r0 = (assistantMode.types.BooleanAnswer) r0
            r1 = 0
            if (r0 == 0) goto L1c
            boolean r2 = r6.a
            boolean r0 = r0.a
            if (r0 != r2) goto L1c
            goto L1d
        L1c:
            r9 = r1
        L1d:
            assistantMode.types.Feedback r0 = new assistantMode.types.Feedback
            assistantMode.types.v r2 = r6.c()
            assistantMode.types.QuestionElement r3 = r6.b
            r4 = 0
            r5 = 24
            r1 = r7
            r0.<init>(r1, r2, r3, r4, r5)
            assistantMode.grading.LocalGradedAnswerMetadata r7 = new assistantMode.grading.LocalGradedAnswerMetadata
            r7.<init>()
            r1 = 0
            r8.<init>(r9, r0, r1, r7)
            return r8
        L36:
            java.lang.StringBuilder r7 = new java.lang.StringBuilder
            java.lang.String r9 = "TrueFalseGrader expected QuestionGraderSettings.None, but received "
            r7.<init>(r9)
            r7.append(r8)
            java.lang.String r7 = r7.toString()
            java.lang.IllegalArgumentException r8 = new java.lang.IllegalArgumentException
            java.lang.String r7 = r7.toString()
            r8.<init>(r7)
            throw r8
        L4e:
            r1 = r7
            java.lang.StringBuilder r7 = new java.lang.StringBuilder
            java.lang.String r8 = "TrueFalseGrader expected BooleanAnswer?, but received "
            r7.<init>(r8)
            r7.append(r1)
            java.lang.String r7 = r7.toString()
            java.lang.IllegalArgumentException r8 = new java.lang.IllegalArgumentException
            java.lang.String r7 = r7.toString()
            r8.<init>(r7)
            throw r8
        */
        throw new UnsupportedOperationException("Method not decompiled: assistantMode.grading.m.a(assistantMode.types.v, com.google.android.gms.internal.mlkit_vision_camera.J2, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    @Override // assistantMode.grading.d
    public final J2 b(grading.core.d assistantSettings) {
        Intrinsics.checkNotNullParameter(assistantSettings, "assistantSettings");
        return f.a;
    }

    @Override // assistantMode.grading.d
    public final v c() {
        return new BooleanAnswer(this.a);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof m)) {
            return false;
        }
        m mVar = (m) obj;
        return this.a == mVar.a && Intrinsics.b(this.b, mVar.b);
    }

    public final int hashCode() {
        return this.b.a.hashCode() + (Boolean.hashCode(this.a) * 31);
    }

    public final String toString() {
        return "TrueFalseGrader(correctOption=" + this.a + ", expectedAnswerDescription=" + this.b + ")";
    }
}

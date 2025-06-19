package assistantMode.types.gradingContext;

import assistantMode.grading.f;
import assistantMode.types.v;
import com.google.android.gms.internal.mlkit_vision_camera.J2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class c implements assistantMode.grading.d {
    public final d a;
    public final int b;

    public c(d grader, int i) {
        Intrinsics.checkNotNullParameter(grader, "grader");
        this.a = grader;
        this.b = i;
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    @Override // assistantMode.grading.d
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object a(assistantMode.types.v r11, com.google.android.gms.internal.mlkit_vision_camera.J2 r12, kotlin.coroutines.jvm.internal.c r13) {
        /*
            Method dump skipped, instructions count: 252
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: assistantMode.types.gradingContext.c.a(assistantMode.types.v, com.google.android.gms.internal.mlkit_vision_camera.J2, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    @Override // assistantMode.grading.d
    public final J2 b(grading.core.d assistantSettings) {
        Intrinsics.checkNotNullParameter(assistantSettings, "assistantSettings");
        return f.a;
    }

    @Override // assistantMode.grading.d
    public final v c() {
        throw new Error("There is no specific expected answer for match questions because there are multiple prompts & answers. Use grader.grade() to get expectedAnswer for a specific prompt.");
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof c)) {
            return false;
        }
        c cVar = (c) obj;
        return Intrinsics.b(this.a, cVar.a) && this.b == cVar.b;
    }

    public final int hashCode() {
        return Integer.hashCode(this.b) + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "MatchingQuestionAnswerGrader(grader=" + this.a + ", promptIndex=" + this.b + ")";
    }
}

package assistantMode.grading;

import assistantMode.types.QuestionElement;
import assistantMode.types.StringAnswer;
import assistantMode.types.v;
import com.google.android.gms.internal.mlkit_vision_camera.J2;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class p implements d {
    public final String a;
    public final QuestionElement b;
    public final Object c;
    public final String d;
    public final String e;
    public final String f;
    public final Object g;

    public p(String expectedAnswer, QuestionElement expectedAnswerDescription, List otherValidAnswers, String str, String str2, String answerLanguageCode) {
        Intrinsics.checkNotNullParameter(expectedAnswer, "expectedAnswer");
        Intrinsics.checkNotNullParameter(expectedAnswerDescription, "expectedAnswerDescription");
        Intrinsics.checkNotNullParameter(otherValidAnswers, "otherValidAnswers");
        Intrinsics.checkNotNullParameter(answerLanguageCode, "answerLanguageCode");
        this.a = expectedAnswer;
        this.b = expectedAnswerDescription;
        this.c = otherValidAnswers;
        this.d = str;
        this.e = str2;
        this.f = answerLanguageCode;
        this.g = kotlin.l.a(kotlin.m.a, new o(0, 0));
    }

    /* JADX WARN: Code restructure failed: missing block: B:36:0x0109, code lost:
    
        if (r1 == r9) goto L37;
     */
    /* JADX WARN: Removed duplicated region for block: B:35:0x00d1  */
    /* JADX WARN: Removed duplicated region for block: B:43:0x0126  */
    /* JADX WARN: Removed duplicated region for block: B:8:0x001c  */
    /* JADX WARN: Type inference failed for: r12v1, types: [java.lang.Object, kotlin.k] */
    /* JADX WARN: Type inference failed for: r3v5, types: [java.lang.Object, kotlin.k] */
    /* JADX WARN: Type inference failed for: r6v5, types: [java.lang.Object, java.util.List] */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:36:0x0109 -> B:38:0x010c). Please report as a decompilation issue!!! */
    @Override // assistantMode.grading.d
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object a(assistantMode.types.v r18, com.google.android.gms.internal.mlkit_vision_camera.J2 r19, kotlin.coroutines.jvm.internal.c r20) {
        /*
            Method dump skipped, instructions count: 358
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: assistantMode.grading.p.a(assistantMode.types.v, com.google.android.gms.internal.mlkit_vision_camera.J2, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    @Override // assistantMode.grading.d
    public final J2 b(grading.core.d assistantSettings) {
        Intrinsics.checkNotNullParameter(assistantSettings, "assistantSettings");
        return new g(new grading.core.d(assistantSettings.a, assistantSettings.b, assistantSettings.c, false, 8));
    }

    @Override // assistantMode.grading.d
    public final v c() {
        return new StringAnswer(this.a);
    }
}

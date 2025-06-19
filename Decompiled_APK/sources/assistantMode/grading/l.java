package assistantMode.grading;

import java.util.Set;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class l implements i {
    public final grading.b a;
    public final kmppUtils.time.a b;
    public final com.quizlet.shared.usecase.grading.c c;

    public l(grading.b localGrader, kmppUtils.time.a timeProvider, com.quizlet.shared.usecase.grading.c cVar) {
        Intrinsics.checkNotNullParameter(localGrader, "localGrader");
        Intrinsics.checkNotNullParameter(timeProvider, "timeProvider");
        this.a = localGrader;
        this.b = timeProvider;
        this.c = cVar;
    }

    /* JADX WARN: Removed duplicated region for block: B:26:0x0079 A[Catch: Exception -> 0x007c, TryCatch #2 {Exception -> 0x007c, blocks: (B:24:0x006b, B:26:0x0079, B:29:0x0080, B:33:0x0086), top: B:44:0x006b }] */
    /* JADX WARN: Removed duplicated region for block: B:28:0x007f  */
    /* JADX WARN: Removed duplicated region for block: B:31:0x0084  */
    /* JADX WARN: Removed duplicated region for block: B:32:0x0085  */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0017  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object a(com.quizlet.shared.usecase.grading.c r17, java.lang.String r18, java.lang.String r19, grading.core.b r20, java.lang.String r21, kotlin.coroutines.jvm.internal.c r22) {
        /*
            Method dump skipped, instructions count: 188
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: assistantMode.grading.l.a(com.quizlet.shared.usecase.grading.c, java.lang.String, java.lang.String, grading.core.b, java.lang.String, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public final Object b(String correctAnswer, String userSubmittedAnswer, grading.core.h hVar, n nVar) {
        grading.core.h hVar2;
        grading.core.d dVar = hVar.d;
        boolean z = dVar.c;
        String answerLanguageCode = hVar.a;
        if (!z || dVar.b) {
            hVar2 = hVar;
        } else {
            grading.core.d gradingSettings = grading.core.d.a(dVar, 13);
            Intrinsics.checkNotNullParameter(answerLanguageCode, "answerLanguage");
            Intrinsics.checkNotNullParameter(gradingSettings, "gradingSettings");
            hVar2 = new grading.core.h(answerLanguageCode, hVar.b, hVar.c, gradingSettings);
        }
        grading.core.b bVarA = ((grading.a) this.a).a(correctAnswer, userSubmittedAnswer, hVar2);
        Set set = assistantMode.utils.a.a;
        Intrinsics.checkNotNullParameter(userSubmittedAnswer, "userSubmittedAnswer");
        Intrinsics.checkNotNullParameter(correctAnswer, "correctAnswer");
        Intrinsics.checkNotNullParameter(answerLanguageCode, "answerLanguageCode");
        boolean z2 = assistantMode.utils.a.a(userSubmittedAnswer) && assistantMode.utils.a.a(correctAnswer) && assistantMode.utils.a.a.contains(answerLanguageCode);
        boolean z3 = bVarA.a;
        com.quizlet.shared.usecase.grading.c cVar = this.c;
        if (cVar == null || !dVar.c || !z2 || z3) {
            return new h(z3, bVarA.b, new LocalGradedAnswerMetadata());
        }
        return a(cVar, correctAnswer, userSubmittedAnswer, bVarA, hVar.a, nVar);
    }
}

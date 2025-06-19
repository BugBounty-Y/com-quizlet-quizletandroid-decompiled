package grading;

import grading.core.c;
import grading.core.d;
import grading.core.e;
import grading.core.g;
import grading.core.h;
import kotlin.Pair;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.Regex;
import kotlin.v;

/* loaded from: classes3.dex */
public final class a implements b {
    public final c[] a;

    public a(c[] rules) {
        Intrinsics.checkNotNullParameter(rules, "rules");
        this.a = rules;
    }

    /* JADX WARN: Type inference failed for: r0v10, types: [kotlin.jvm.functions.c, kotlin.jvm.internal.r] */
    public final grading.core.b a(String correctAnswer, String userSubmission, h hVar) {
        Object obj;
        Object obj2;
        Object obj3;
        e eVar;
        h other = hVar;
        Intrinsics.checkNotNullParameter(correctAnswer, "correctAnswer");
        Intrinsics.checkNotNullParameter(userSubmission, "userSubmission");
        Intrinsics.checkNotNullParameter(other, "submissionContext");
        String strA = util.b.a(correctAnswer);
        Intrinsics.checkNotNullParameter(strA, "<this>");
        Regex regex = g.c;
        util.a aVar = util.a.c;
        String answerText = regex.f(strA, aVar);
        String strA2 = util.b.a(userSubmission);
        Intrinsics.checkNotNullParameter(strA2, "<this>");
        String submissionText = regex.f(strA2, aVar);
        c[] cVarArr = this.a;
        int length = cVarArr.length;
        int i = 0;
        e eVar2 = null;
        while (i < length) {
            c cVar = cVarArr[i];
            cVar.getClass();
            Intrinsics.checkNotNullParameter(answerText, "answerText");
            Intrinsics.checkNotNullParameter(submissionText, "submissionText");
            Intrinsics.checkNotNullParameter(other, "submissionContext");
            d gradingSettings = new d(false, false, false, false, 8);
            String answerLanguage = cVar.b;
            Intrinsics.checkNotNullParameter(answerLanguage, "answerLanguage");
            Intrinsics.checkNotNullParameter(gradingSettings, "gradingSettings");
            Intrinsics.checkNotNullParameter(other, "other");
            String str = other.a;
            if (str.length() != 0) {
                answerLanguage = str;
            }
            String str2 = other.b;
            if (str2 == null || str2.length() == 0) {
                str2 = cVar.c;
            }
            c[] cVarArr2 = cVarArr;
            String str3 = other.c;
            if (str3 == null || str3.length() == 0) {
                str3 = "";
            }
            int i2 = length;
            d other2 = other.d;
            Intrinsics.checkNotNullParameter(other2, "other");
            int i3 = i;
            e eVar3 = eVar2;
            h submissionContext = new h(answerLanguage, str2, str3, new d(gradingSettings.a || other2.a, gradingSettings.b || other2.b, gradingSettings.c || other2.c, gradingSettings.d || other2.d));
            Intrinsics.checkNotNullParameter(answerText, "answerText");
            Intrinsics.checkNotNullParameter(submissionText, "submissionText");
            Intrinsics.checkNotNullParameter(submissionContext, "submissionContext");
            e eVar4 = null;
            v input = new v(answerText, submissionText, null);
            grading.core.a[] aVarArr = cVar.d;
            int length2 = aVarArr.length;
            int i4 = 0;
            while (true) {
                obj = input.c;
                obj2 = input.b;
                obj3 = input.a;
                if (i4 >= length2) {
                    break;
                }
                grading.core.a clause = aVarArr[i4];
                Intrinsics.checkNotNullParameter(clause, "clause");
                Intrinsics.checkNotNullParameter(input, "input");
                Intrinsics.checkNotNullParameter(submissionContext, "submissionContext");
                String str4 = (String) obj3;
                String str5 = (String) obj2;
                Pair pair = ((Boolean) clause.a.invoke(str4, str5, submissionContext)).booleanValue() ? (Pair) clause.c.invoke(str4, str5) : new Pair(str4, str5);
                String str6 = (String) pair.a;
                String str7 = (String) pair.b;
                grading.core.enums.a aVar2 = clause.b;
                if (aVar2 == null) {
                    eVar = eVar4;
                } else if (Intrinsics.b(str4, str5) || !Intrinsics.b(str6, str7)) {
                    eVar = null;
                } else {
                    eVar = new e(clause.a(submissionContext) ? grading.core.enums.b.b : grading.core.enums.b.a, aVar2);
                }
                if (clause.a(submissionContext)) {
                    str5 = str7;
                    str4 = str6;
                }
                e eVar5 = (e) obj;
                if (eVar5 != null) {
                    eVar = eVar5;
                }
                input = new v(str4, str5, eVar);
                i4++;
                eVar4 = null;
            }
            e eVar6 = (e) obj;
            boolean zB = Intrinsics.b((String) obj3, (String) obj2);
            grading.core.b bVar = new grading.core.b(zB, eVar6);
            if (zB) {
                return bVar;
            }
            eVar2 = eVar6 == null ? eVar3 : eVar6;
            i = i3 + 1;
            other = hVar;
            cVarArr = cVarArr2;
            length = i2;
        }
        return new grading.core.b(false, eVar2);
    }
}

package grading.impls;

import kotlin.Pair;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.r;
import kotlin.text.Regex;

/* loaded from: classes3.dex */
public final class e extends r implements Function2 {
    public static final e b = new e(2, 0);
    public static final e c = new e(2, 1);
    public static final e d = new e(2, 2);
    public static final e e = new e(2, 3);
    public static final e f = new e(2, 4);
    public static final e g = new e(2, 5);
    public static final e h = new e(2, 6);
    public static final e i = new e(2, 7);
    public final /* synthetic */ int a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ e(int i2, int i3) {
        super(i2);
        this.a = i3;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        Regex regex = null;
        int i2 = 0;
        switch (this.a) {
            case 0:
                String answer = (String) obj;
                String test2 = (String) obj2;
                Intrinsics.checkNotNullParameter(answer, "answer");
                Intrinsics.checkNotNullParameter(test2, "test");
                return new Pair(answer, grading.core.g.i.replace(test2, " "));
            case 1:
                String answer2 = (String) obj;
                String test3 = (String) obj2;
                Intrinsics.checkNotNullParameter(answer2, "answer");
                Intrinsics.checkNotNullParameter(test3, "test");
                Regex[] regexArr = grading.core.g.l;
                int length = regexArr.length;
                while (true) {
                    if (i2 < length) {
                        Regex regex2 = regexArr[i2];
                        if (regex2.a(answer2) && regex2.a(test3)) {
                            regex = regex2;
                        } else {
                            i2++;
                        }
                    }
                }
                return regex != null ? f.a(regex, answer2, test3) : new Pair(answer2, test3);
            case 2:
                String answer3 = (String) obj;
                String test4 = (String) obj2;
                Intrinsics.checkNotNullParameter(answer3, "answer");
                Intrinsics.checkNotNullParameter(test4, "test");
                Regex[] regexArr2 = grading.core.g.m;
                int length2 = regexArr2.length;
                while (true) {
                    if (i2 < length2) {
                        Regex regex3 = regexArr2[i2];
                        if (regex3.a(answer3) && regex3.a(test4)) {
                            regex = regex3;
                        } else {
                            i2++;
                        }
                    }
                }
                return regex != null ? f.a(regex, answer3, test4) : new Pair(answer3, test4);
            case 3:
                String answer4 = (String) obj;
                String test5 = (String) obj2;
                Intrinsics.checkNotNullParameter(answer4, "answer");
                Intrinsics.checkNotNullParameter(test5, "test");
                grading.core.a aVar = f.a;
                return f.a(grading.core.g.i, answer4, test5);
            case 4:
                String answer5 = (String) obj;
                String test6 = (String) obj2;
                Intrinsics.checkNotNullParameter(answer5, "answer");
                Intrinsics.checkNotNullParameter(test6, "test");
                grading.core.a aVar2 = f.a;
                return f.a(grading.core.g.i, answer5, test6);
            case 5:
                String answer6 = (String) obj;
                String test7 = (String) obj2;
                Intrinsics.checkNotNullParameter(answer6, "answer");
                Intrinsics.checkNotNullParameter(test7, "test");
                return new Pair(answer6, grading.core.g.i.replace(test7, ""));
            case 6:
                String answer7 = (String) obj;
                String test8 = (String) obj2;
                Intrinsics.checkNotNullParameter(answer7, "answer");
                Intrinsics.checkNotNullParameter(test8, "test");
                return new Pair(answer7, grading.core.g.i.replace(test8, ""));
            default:
                String answer8 = (String) obj;
                Intrinsics.checkNotNullParameter(answer8, "answer");
                Intrinsics.checkNotNullParameter((String) obj2, "<anonymous parameter 1>");
                return new Pair(answer8, answer8);
        }
    }
}

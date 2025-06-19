package grading.impls.levenshteinplus;

import com.google.android.gms.internal.mlkit_vision_camera.j3;
import grading.core.g;
import grading.core.h;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.r;
import kotlin.sequences.q;
import kotlin.text.Regex;

/* loaded from: classes3.dex */
public final class a extends r implements kotlin.jvm.functions.c {
    public static final a b = new a(3, 0);
    public static final a c = new a(3, 1);
    public final /* synthetic */ int a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ a(int i, int i2) {
        super(i);
        this.a = i2;
    }

    @Override // kotlin.jvm.functions.c
    public final Object invoke(Object obj, Object obj2, Object obj3) {
        boolean z = false;
        switch (this.a) {
            case 0:
                String answer = (String) obj;
                String userInput = (String) obj2;
                Intrinsics.checkNotNullParameter(answer, "answer");
                Intrinsics.checkNotNullParameter(userInput, "userInput");
                Intrinsics.checkNotNullParameter((h) obj3, "<anonymous parameter 2>");
                grading.core.a aVar = c.a;
                Intrinsics.checkNotNullParameter(answer, "answer");
                if (answer.length() > 5) {
                    Intrinsics.checkNotNullParameter(answer, "answer");
                    Intrinsics.checkNotNullParameter(userInput, "userInput");
                    Regex regex = g.s;
                    kotlin.sequences.g gVarC = Regex.c(regex, answer);
                    kotlin.sequences.g gVarC2 = Regex.c(regex, userInput);
                    if (q.d(gVarC) != q.d(gVarC2) ? false : Intrinsics.b(q.j(q.h(gVarC, b.b)), q.j(q.h(gVarC2, b.c)))) {
                        Intrinsics.checkNotNullParameter(answer, "answer");
                        Intrinsics.checkNotNullParameter(userInput, "userInput");
                        int iC = j3.c(answer, userInput);
                        if (iC == 1 || ((double) iC) / ((double) answer.length()) <= 0.15d) {
                            z = true;
                        }
                    }
                }
                return Boolean.valueOf(z);
            default:
                String answer2 = (String) obj;
                String userInput2 = (String) obj2;
                h hVar = (h) obj3;
                Intrinsics.checkNotNullParameter(answer2, "answer");
                Intrinsics.checkNotNullParameter(userInput2, "userInput");
                Intrinsics.checkNotNullParameter(hVar, "<name for destructuring parameter 2>");
                String str = hVar.a;
                if (Intrinsics.b(hVar.b, "en") && Intrinsics.b(str, "en")) {
                    Regex regex2 = g.i;
                    if (regex2.a(answer2) || regex2.a(userInput2)) {
                        z = true;
                    }
                }
                return Boolean.valueOf(z);
        }
    }
}

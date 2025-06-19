package assistantMode.types;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: assistantMode.types.b, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1455b {
    public final boolean a;
    public final assistantMode.enums.m b;
    public final assistantMode.enums.m c;
    public final assistantMode.enums.k d;
    public final long e;
    public final long f;

    public C1455b(boolean z, assistantMode.enums.m promptSide, assistantMode.enums.m answerSide, assistantMode.enums.k questionType, long j, long j2) {
        Intrinsics.checkNotNullParameter(promptSide, "promptSide");
        Intrinsics.checkNotNullParameter(answerSide, "answerSide");
        Intrinsics.checkNotNullParameter(questionType, "questionType");
        this.a = z;
        this.b = promptSide;
        this.c = answerSide;
        this.d = questionType;
        this.e = j;
        this.f = j2;
    }

    /* JADX WARN: Removed duplicated region for block: B:13:0x001f  */
    /* JADX WARN: Removed duplicated region for block: B:15:0x003e A[RETURN] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final assistantMode.types.C1455b a() {
        /*
            r11 = this;
            java.lang.String r0 = "<this>"
            assistantMode.enums.k r1 = r11.d
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r1, r0)
            int r0 = r1.ordinal()
            r2 = 3
            if (r0 == r2) goto L1a
            r2 = 5
            if (r0 == r2) goto L1a
            r2 = 6
            if (r0 == r2) goto L16
            r6 = r1
            goto L1d
        L16:
            assistantMode.enums.k r0 = assistantMode.enums.k.b
        L18:
            r6 = r0
            goto L1d
        L1a:
            assistantMode.enums.k r0 = assistantMode.enums.k.d
            goto L18
        L1d:
            if (r6 == r1) goto L3e
            assistantMode.enums.m r4 = r11.b
            java.lang.String r0 = "promptSide"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r4, r0)
            assistantMode.enums.m r5 = r11.c
            java.lang.String r0 = "answerSide"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r5, r0)
            java.lang.String r0 = "questionType"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r6, r0)
            assistantMode.types.b r2 = new assistantMode.types.b
            long r7 = r11.e
            long r9 = r11.f
            boolean r3 = r11.a
            r2.<init>(r3, r4, r5, r6, r7, r9)
            return r2
        L3e:
            return r11
        */
        throw new UnsupportedOperationException("Method not decompiled: assistantMode.types.C1455b.a():assistantMode.types.b");
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C1455b)) {
            return false;
        }
        C1455b c1455b = (C1455b) obj;
        return this.a == c1455b.a && this.b == c1455b.b && this.c == c1455b.c && this.d == c1455b.d && this.e == c1455b.e && this.f == c1455b.f;
    }

    public final int hashCode() {
        return Long.hashCode(this.f) + d0.d((this.d.hashCode() + assistantMode.refactored.a.e(this.c, assistantMode.refactored.a.e(this.b, Boolean.hashCode(this.a) * 31, 31), 31)) * 31, 31, this.e);
    }

    public final String toString() {
        return "Answer(isCorrect=" + this.a + ", promptSide=" + this.b + ", answerSide=" + this.c + ", questionType=" + this.d + ", studiableItemId=" + this.e + ", timestamp=" + this.f + ")";
    }
}

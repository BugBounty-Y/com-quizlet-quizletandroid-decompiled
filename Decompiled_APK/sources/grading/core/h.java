package grading.core;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class h {
    public final String a;
    public final String b;
    public final String c;
    public final d d;

    public h(String answerLanguage, String str, String str2, d gradingSettings) {
        Intrinsics.checkNotNullParameter(answerLanguage, "answerLanguage");
        Intrinsics.checkNotNullParameter(gradingSettings, "gradingSettings");
        this.a = answerLanguage;
        this.b = str;
        this.c = str2;
        this.d = gradingSettings;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof h)) {
            return false;
        }
        h hVar = (h) obj;
        return Intrinsics.b(this.a, hVar.a) && Intrinsics.b(this.b, hVar.b) && Intrinsics.b(this.c, hVar.c) && Intrinsics.b(this.d, hVar.d);
    }

    public final int hashCode() {
        int iHashCode = this.a.hashCode() * 31;
        String str = this.b;
        int iHashCode2 = (iHashCode + (str == null ? 0 : str.hashCode())) * 31;
        String str2 = this.c;
        return this.d.hashCode() + ((iHashCode2 + (str2 != null ? str2.hashCode() : 0)) * 31);
    }

    public final String toString() {
        return "SubmissionContext(answerLanguage=" + this.a + ", promptLanguage=" + this.b + ", promptText=" + this.c + ", gradingSettings=" + this.d + ")";
    }
}

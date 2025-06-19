package grading.core;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class c {
    public final String a;
    public final String b;
    public final String c;
    public final a[] d;

    public c(String name, String answerLanguage, String promptLanguage, a[] clauses) {
        Intrinsics.checkNotNullParameter(name, "name");
        Intrinsics.checkNotNullParameter(answerLanguage, "answerLanguage");
        Intrinsics.checkNotNullParameter(promptLanguage, "promptLanguage");
        Intrinsics.checkNotNullParameter(clauses, "clauses");
        this.a = name;
        this.b = answerLanguage;
        this.c = promptLanguage;
        this.d = clauses;
    }
}

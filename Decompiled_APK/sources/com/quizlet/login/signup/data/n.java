package com.quizlet.login.signup.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class n implements q {
    public final PromptParentEmailData a;

    public n(PromptParentEmailData promptParentEmailData) {
        Intrinsics.checkNotNullParameter(promptParentEmailData, "promptParentEmailData");
        this.a = promptParentEmailData;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof n) && Intrinsics.b(this.a, ((n) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "PromptParentEmail(promptParentEmailData=" + this.a + ")";
    }
}

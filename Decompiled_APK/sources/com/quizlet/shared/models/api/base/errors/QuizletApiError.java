package com.quizlet.shared.models.api.base.errors;

import assistantMode.refactored.a;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.f;
import org.jetbrains.annotations.NotNull;

@f
@Metadata
/* loaded from: classes3.dex */
public final class QuizletApiError {

    @NotNull
    public static final Companion Companion = new Companion();
    public final String a;
    public final String b;
    public final Integer c;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return QuizletApiError$$serializer.INSTANCE;
        }
    }

    public QuizletApiError(String str) {
        this.a = str;
        this.b = null;
        this.c = null;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof QuizletApiError)) {
            return false;
        }
        QuizletApiError quizletApiError = (QuizletApiError) obj;
        return Intrinsics.b(this.a, quizletApiError.a) && Intrinsics.b(this.b, quizletApiError.b) && Intrinsics.b(this.c, quizletApiError.c);
    }

    public final int hashCode() {
        String str = this.a;
        int iHashCode = (str == null ? 0 : str.hashCode()) * 31;
        String str2 = this.b;
        int iHashCode2 = (iHashCode + (str2 == null ? 0 : str2.hashCode())) * 31;
        Integer num = this.c;
        return iHashCode2 + (num != null ? num.hashCode() : 0);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("QuizletApiError(message=");
        sb.append(this.a);
        sb.append(", identifier=");
        sb.append(this.b);
        sb.append(", code=");
        return a.l(sb, this.c, ")");
    }

    public /* synthetic */ QuizletApiError(String str, String str2, Integer num, int i) {
        if ((i & 1) == 0) {
            this.a = null;
        } else {
            this.a = str;
        }
        if ((i & 2) == 0) {
            this.b = null;
        } else {
            this.b = str2;
        }
        if ((i & 4) == 0) {
            this.c = null;
        } else {
            this.c = num;
        }
    }
}

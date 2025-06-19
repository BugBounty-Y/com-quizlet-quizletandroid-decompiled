package com.quizlet.data.model;

import com.quizlet.generated.enums.EnumC4534z;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class S0 {
    public final String a;
    public final String b;
    public final EnumC4534z c;
    public final String d;
    public final String e;
    public final com.quizlet.generated.enums.E0 f;
    public final long g;

    public S0(String uuid, String name, EnumC4534z documentType, String createdAt, String str, com.quizlet.generated.enums.E0 e0) {
        Intrinsics.checkNotNullParameter(uuid, "uuid");
        Intrinsics.checkNotNullParameter(name, "name");
        Intrinsics.checkNotNullParameter(documentType, "documentType");
        Intrinsics.checkNotNullParameter(createdAt, "createdAt");
        this.a = uuid;
        this.b = name;
        this.c = documentType;
        this.d = createdAt;
        this.e = str;
        this.f = e0;
        this.g = Instant.from(DateTimeFormatter.ISO_INSTANT.parse(createdAt)).toEpochMilli();
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof S0)) {
            return false;
        }
        S0 s0 = (S0) obj;
        return Intrinsics.b(this.a, s0.a) && Intrinsics.b(this.b, s0.b) && this.c == s0.c && Intrinsics.b(this.d, s0.d) && Intrinsics.b(this.e, s0.e) && this.f == s0.f;
    }

    public final int hashCode() {
        int iE = androidx.compose.animation.d0.e((this.c.hashCode() + androidx.compose.animation.d0.e(this.a.hashCode() * 31, 31, this.b)) * 31, 31, this.d);
        String str = this.e;
        int iHashCode = (iE + (str == null ? 0 : str.hashCode())) * 31;
        com.quizlet.generated.enums.E0 e0 = this.f;
        return iHashCode + (e0 != null ? e0.hashCode() : 0);
    }

    public final String toString() {
        return "PracticeTestInfoItem(uuid=" + this.a + ", name=" + this.b + ", documentType=" + this.c + ", createdAt=" + this.d + ", fileName=" + this.e + ", uploadEntryPoint=" + this.f + ")";
    }
}

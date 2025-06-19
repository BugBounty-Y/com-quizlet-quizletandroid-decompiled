package com.quizlet.data.model;

import com.quizlet.generated.enums.EnumC4479f;
import java.time.LocalDateTime;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class C2 {
    public final int a;
    public final EnumC4479f b;
    public final LocalDateTime c;

    public C2(int i, EnumC4479f progressType, LocalDateTime localDateTime) {
        Intrinsics.checkNotNullParameter(progressType, "progressType");
        this.a = i;
        this.b = progressType;
        this.c = localDateTime;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C2)) {
            return false;
        }
        C2 c2 = (C2) obj;
        return this.a == c2.a && this.b == c2.b && Intrinsics.b(this.c, c2.c);
    }

    public final int hashCode() {
        int iHashCode = (this.b.hashCode() + (Integer.hashCode(this.a) * 31)) * 31;
        LocalDateTime localDateTime = this.c;
        return iHashCode + (localDateTime == null ? 0 : localDateTime.hashCode());
    }

    public final String toString() {
        return "StreakData(length=" + this.a + ", progressType=" + this.b + ", lastHistoryDate=" + this.c + ")";
    }
}

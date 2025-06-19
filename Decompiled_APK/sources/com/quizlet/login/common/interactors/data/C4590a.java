package com.quizlet.login.common.interactors.data;

/* renamed from: com.quizlet.login.common.interactors.data.a, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4590a {
    public final long a;
    public final int b;

    public C4590a(int i, long j) {
        this.a = j;
        this.b = i;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C4590a)) {
            return false;
        }
        C4590a c4590a = (C4590a) obj;
        return this.a == c4590a.a && this.b == c4590a.b;
    }

    public final int hashCode() {
        return Integer.hashCode(this.b) + (Long.hashCode(this.a) * 31);
    }

    public final String toString() {
        return "CalendarData(selectableDate=" + this.a + ", selectableYear=" + this.b + ")";
    }
}

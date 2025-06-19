package com.google.firebase.sessions;

import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.firebase.sessions.v, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3999v {
    public final String a;

    public C3999v(String str) {
        this.a = str;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof C3999v) && Intrinsics.b(this.a, ((C3999v) obj).a);
    }

    public final int hashCode() {
        String str = this.a;
        if (str == null) {
            return 0;
        }
        return str.hashCode();
    }

    public final String toString() {
        return androidx.compose.animation.d0.r(new StringBuilder("FirebaseSessionsData(sessionId="), this.a, ')');
    }
}

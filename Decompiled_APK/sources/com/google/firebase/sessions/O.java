package com.google.firebase.sessions;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class O {
    public final Y a;
    public final C3980b b;

    public O(Y sessionData, C3980b applicationInfo) {
        EnumC3992n eventType = EnumC3992n.SESSION_START;
        Intrinsics.checkNotNullParameter(eventType, "eventType");
        Intrinsics.checkNotNullParameter(sessionData, "sessionData");
        Intrinsics.checkNotNullParameter(applicationInfo, "applicationInfo");
        this.a = sessionData;
        this.b = applicationInfo;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof O)) {
            return false;
        }
        O o = (O) obj;
        o.getClass();
        return this.a.equals(o.a) && this.b.equals(o.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + ((this.a.hashCode() + (EnumC3992n.SESSION_START.hashCode() * 31)) * 31);
    }

    public final String toString() {
        return "SessionEvent(eventType=" + EnumC3992n.SESSION_START + ", sessionData=" + this.a + ", applicationInfo=" + this.b + ')';
    }
}

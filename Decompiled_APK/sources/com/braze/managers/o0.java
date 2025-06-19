package com.braze.managers;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class o0 {
    public boolean a;
    public Long b;
    public String c;
    public long d;
    public long e;
    public long f;

    public /* synthetic */ o0() {
        this(false, null, null, 0L, 0L, 0L);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof o0)) {
            return false;
        }
        o0 o0Var = (o0) obj;
        return this.a == o0Var.a && Intrinsics.b(this.b, o0Var.b) && Intrinsics.b(this.c, o0Var.c) && this.d == o0Var.d && this.e == o0Var.e && this.f == o0Var.f;
    }

    public final int hashCode() {
        int iHashCode = Boolean.hashCode(this.a) * 31;
        Long l = this.b;
        int iHashCode2 = (iHashCode + (l == null ? 0 : l.hashCode())) * 31;
        String str = this.c;
        return Long.hashCode(this.f) + androidx.compose.animation.d0.d(androidx.compose.animation.d0.d((iHashCode2 + (str != null ? str.hashCode() : 0)) * 31, 31, this.d), 31, this.e);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("Config(isEnabled=");
        sb.append(this.a);
        sb.append(", sdkDebuggerExpirationTime=");
        sb.append(this.b);
        sb.append(", sdkDebuggerAuthCode=");
        sb.append(this.c);
        sb.append(", sdkDebuggerFlushIntervalBytes=");
        sb.append(this.d);
        sb.append(", sdkDebuggerFlushIntervalSeconds=");
        sb.append(this.e);
        sb.append(", sdkDebuggerMaxPayloadBytes=");
        return androidx.compose.animation.d0.q(sb, this.f, ')');
    }

    public o0(boolean z, Long l, String str, long j, long j2, long j3) {
        this.a = z;
        this.b = l;
        this.c = str;
        this.d = j;
        this.e = j2;
        this.f = j3;
    }
}

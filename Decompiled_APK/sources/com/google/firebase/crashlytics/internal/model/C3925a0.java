package com.google.firebase.crashlytics.internal.model;

/* renamed from: com.google.firebase.crashlytics.internal.model.a0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3925a0 extends D0 {
    public final String a;
    public final int b;
    public final int c;
    public final boolean d;

    public C3925a0(int i, int i2, String str, boolean z) {
        this.a = str;
        this.b = i;
        this.c = i2;
        this.d = z;
    }

    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj instanceof D0) {
            D0 d0 = (D0) obj;
            if (this.a.equals(((C3925a0) d0).a)) {
                C3925a0 c3925a0 = (C3925a0) d0;
                if (this.b == c3925a0.b && this.c == c3925a0.c && this.d == c3925a0.d) {
                    return true;
                }
            }
        }
        return false;
    }

    public final int hashCode() {
        return ((((((this.a.hashCode() ^ 1000003) * 1000003) ^ this.b) * 1000003) ^ this.c) * 1000003) ^ (this.d ? 1231 : 1237);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("ProcessDetails{processName=");
        sb.append(this.a);
        sb.append(", pid=");
        sb.append(this.b);
        sb.append(", importance=");
        sb.append(this.c);
        sb.append(", defaultProcess=");
        return android.support.v4.media.session.a.o("}", sb, this.d);
    }
}

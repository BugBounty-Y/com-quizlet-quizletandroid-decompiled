package com.google.android.gms.ads.internal.util.client;

/* loaded from: classes2.dex */
public final class g {
    public final int a;
    public final int b;
    public final boolean c;

    public g(int i, int i2, boolean z) {
        this.a = i;
        this.b = i2;
        this.c = z;
    }

    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj instanceof g) {
            g gVar = (g) obj;
            if (this.a == gVar.a && this.b == gVar.b && this.c == gVar.c) {
                return true;
            }
        }
        return false;
    }

    public final int hashCode() {
        return (true != this.c ? 1237 : 1231) ^ ((((this.a ^ 1000003) * 1000003) ^ this.b) * 1000003);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("OfflineAdConfig{impressionPrerequisite=");
        sb.append(this.a);
        sb.append(", clickPrerequisite=");
        sb.append(this.b);
        sb.append(", notificationFlowEnabled=");
        return android.support.v4.media.session.a.o("}", sb, this.c);
    }
}

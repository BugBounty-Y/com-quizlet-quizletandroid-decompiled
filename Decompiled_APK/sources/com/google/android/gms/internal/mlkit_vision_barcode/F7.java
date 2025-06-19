package com.google.android.gms.internal.mlkit_vision_barcode;

/* loaded from: classes2.dex */
public final class F7 {
    public final String a;
    public final int b;

    public F7(String str, int i) {
        this.a = str;
        this.b = i;
    }

    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (!(obj instanceof F7)) {
            return false;
        }
        F7 f7 = (F7) obj;
        return this.a.equals(f7.a) && this.b == f7.b;
    }

    public final int hashCode() {
        return ((((this.a.hashCode() ^ 1000003) * 1000003) ^ 1231) * 1000003) ^ this.b;
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("MLKitLoggingOptions{libraryName=");
        sb.append(this.a);
        sb.append(", enableFirelog=true, firelogEventType=");
        return android.support.v4.media.session.a.r(sb, this.b, "}");
    }
}

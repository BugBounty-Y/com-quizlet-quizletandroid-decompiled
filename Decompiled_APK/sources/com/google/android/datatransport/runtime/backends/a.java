package com.google.android.datatransport.runtime.backends;

import androidx.camera.camera2.internal.AbstractC0147y;

/* loaded from: classes2.dex */
public final class a {
    public final int a;
    public final long b;

    public a(int i, long j) {
        if (i == 0) {
            throw new NullPointerException("Null status");
        }
        this.a = i;
        this.b = j;
    }

    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (!(obj instanceof a)) {
            return false;
        }
        a aVar = (a) obj;
        return AbstractC0147y.a(this.a, aVar.a) && this.b == aVar.b;
    }

    public final int hashCode() {
        int iK = (AbstractC0147y.k(this.a) ^ 1000003) * 1000003;
        long j = this.b;
        return iK ^ ((int) (j ^ (j >>> 32)));
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("BackendResponse{status=");
        int i = this.a;
        sb.append(i != 1 ? i != 2 ? i != 3 ? i != 4 ? "null" : "INVALID_PAYLOAD" : "FATAL_ERROR" : "TRANSIENT_ERROR" : "OK");
        sb.append(", nextRequestWaitMillis=");
        return android.support.v4.media.session.a.g(this.b, "}", sb);
    }
}

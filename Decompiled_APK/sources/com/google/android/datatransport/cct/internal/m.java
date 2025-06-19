package com.google.android.datatransport.cct.internal;

import androidx.camera.camera2.internal.AbstractC0147y;
import java.util.ArrayList;

/* loaded from: classes2.dex */
public final class m extends x {
    public final ArrayList a;

    public m(ArrayList arrayList) {
        this.a = arrayList;
    }

    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (!(obj instanceof x)) {
            return false;
        }
        return this.a.equals(((m) ((x) obj)).a);
    }

    public final int hashCode() {
        return this.a.hashCode() ^ 1000003;
    }

    public final String toString() {
        return AbstractC0147y.f("}", new StringBuilder("BatchedLogRequest{logRequests="), this.a);
    }
}

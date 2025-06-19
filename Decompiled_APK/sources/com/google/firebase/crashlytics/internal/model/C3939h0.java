package com.google.firebase.crashlytics.internal.model;

import java.util.List;

/* renamed from: com.google.firebase.crashlytics.internal.model.h0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3939h0 extends J0 {
    public final List a;

    public C3939h0(List list) {
        this.a = list;
    }

    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (!(obj instanceof J0)) {
            return false;
        }
        return this.a.equals(((C3939h0) ((J0) obj)).a);
    }

    public final int hashCode() {
        return this.a.hashCode() ^ 1000003;
    }

    public final String toString() {
        return android.support.v4.media.session.a.n("}", new StringBuilder("RolloutsState{rolloutAssignments="), this.a);
    }
}

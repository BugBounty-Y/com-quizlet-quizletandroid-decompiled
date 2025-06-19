package com.google.firebase.crashlytics.internal.model;

import java.util.List;

/* loaded from: classes2.dex */
public final class Q extends E0 {
    public final S a;
    public final List b;
    public final List c;
    public final Boolean d;
    public final D0 e;
    public final List f;
    public final int g;

    public Q(S s, List list, List list2, Boolean bool, D0 d0, List list3, int i) {
        this.a = s;
        this.b = list;
        this.c = list2;
        this.d = bool;
        this.e = d0;
        this.f = list3;
        this.g = i;
    }

    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (!(obj instanceof E0)) {
            return false;
        }
        Q q = (Q) ((E0) obj);
        if (!this.a.equals(q.a)) {
            return false;
        }
        List list = this.b;
        if (list == null) {
            if (q.b != null) {
                return false;
            }
        } else if (!list.equals(q.b)) {
            return false;
        }
        List list2 = this.c;
        if (list2 == null) {
            if (q.c != null) {
                return false;
            }
        } else if (!list2.equals(q.c)) {
            return false;
        }
        Boolean bool = this.d;
        if (bool == null) {
            if (q.d != null) {
                return false;
            }
        } else if (!bool.equals(q.d)) {
            return false;
        }
        D0 d0 = this.e;
        if (d0 == null) {
            if (q.e != null) {
                return false;
            }
        } else if (!d0.equals(q.e)) {
            return false;
        }
        List list3 = this.f;
        if (list3 == null) {
            if (q.f != null) {
                return false;
            }
        } else if (!list3.equals(q.f)) {
            return false;
        }
        return this.g == q.g;
    }

    public final int hashCode() {
        int iHashCode = (this.a.hashCode() ^ 1000003) * 1000003;
        List list = this.b;
        int iHashCode2 = (iHashCode ^ (list == null ? 0 : list.hashCode())) * 1000003;
        List list2 = this.c;
        int iHashCode3 = (iHashCode2 ^ (list2 == null ? 0 : list2.hashCode())) * 1000003;
        Boolean bool = this.d;
        int iHashCode4 = (iHashCode3 ^ (bool == null ? 0 : bool.hashCode())) * 1000003;
        D0 d0 = this.e;
        int iHashCode5 = (iHashCode4 ^ (d0 == null ? 0 : d0.hashCode())) * 1000003;
        List list3 = this.f;
        return ((iHashCode5 ^ (list3 != null ? list3.hashCode() : 0)) * 1000003) ^ this.g;
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("Application{execution=");
        sb.append(this.a);
        sb.append(", customAttributes=");
        sb.append(this.b);
        sb.append(", internalKeys=");
        sb.append(this.c);
        sb.append(", background=");
        sb.append(this.d);
        sb.append(", currentProcessDetails=");
        sb.append(this.e);
        sb.append(", appProcessDetails=");
        sb.append(this.f);
        sb.append(", uiOrientation=");
        return android.support.v4.media.session.a.r(sb, this.g, "}");
    }
}

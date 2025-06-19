package com.google.android.gms.internal.ads;

import java.io.Serializable;

/* loaded from: classes2.dex */
public final class Iu extends Au implements Serializable {
    @Override // java.util.Comparator
    public final int compare(Object obj, Object obj2) {
        return VF.i.compare(obj2, obj);
    }

    @Override // java.util.Comparator
    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (!(obj instanceof Iu)) {
            return false;
        }
        C1853au c1853au = VF.i;
        ((Iu) obj).getClass();
        return c1853au.equals(c1853au);
    }

    public final int hashCode() {
        return -VF.i.hashCode();
    }

    public final String toString() {
        return VF.i.toString().concat(".reverse()");
    }
}

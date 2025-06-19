package com.google.android.gms.internal.ads;

import java.util.Arrays;
import java.util.List;

/* loaded from: classes2.dex */
public final class K4 {
    public final InterfaceC2856y4[] a;

    public K4(InterfaceC2856y4... interfaceC2856y4Arr) {
        this.a = interfaceC2856y4Arr;
    }

    public final K4 a(InterfaceC2856y4... interfaceC2856y4Arr) {
        int length = interfaceC2856y4Arr.length;
        if (length == 0) {
            return this;
        }
        String str = Yo.a;
        InterfaceC2856y4[] interfaceC2856y4Arr2 = this.a;
        int length2 = interfaceC2856y4Arr2.length;
        Object[] objArrCopyOf = Arrays.copyOf(interfaceC2856y4Arr2, length2 + length);
        System.arraycopy(interfaceC2856y4Arr, 0, objArrCopyOf, length2, length);
        return new K4((InterfaceC2856y4[]) objArrCopyOf);
    }

    public final K4 b(K4 k4) {
        return k4 == null ? this : a(k4.a);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return obj != null && K4.class == obj.getClass() && Arrays.equals(this.a, ((K4) obj).a);
    }

    public final int hashCode() {
        return (Arrays.hashCode(this.a) * 31) + ((int) (-9223372034707292159L));
    }

    public final String toString() {
        return android.support.v4.media.session.a.B("entries=", Arrays.toString(this.a), "");
    }

    public K4(List list) {
        this.a = (InterfaceC2856y4[]) list.toArray(new InterfaceC2856y4[0]);
    }
}

package com.google.android.datatransport.cct.internal;

import java.util.Arrays;

/* loaded from: classes2.dex */
public final class p extends C {
    public final byte[] a;
    public final byte[] b;

    public p(byte[] bArr, byte[] bArr2) {
        this.a = bArr;
        this.b = bArr2;
    }

    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj instanceof C) {
            C c = (C) obj;
            boolean z = c instanceof p;
            if (Arrays.equals(this.a, z ? ((p) c).a : ((p) c).a)) {
                if (Arrays.equals(this.b, z ? ((p) c).b : ((p) c).b)) {
                    return true;
                }
            }
        }
        return false;
    }

    public final int hashCode() {
        return ((Arrays.hashCode(this.a) ^ 1000003) * 1000003) ^ Arrays.hashCode(this.b);
    }

    public final String toString() {
        return "ExperimentIds{clearBlob=" + Arrays.toString(this.a) + ", encryptedBlob=" + Arrays.toString(this.b) + "}";
    }
}

package com.google.firebase.crashlytics.internal.model;

import java.util.Arrays;

/* loaded from: classes2.dex */
public final class H extends s0 {
    public final String a;
    public final byte[] b;

    public H(String str, byte[] bArr) {
        this.a = str;
        this.b = bArr;
    }

    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj instanceof s0) {
            s0 s0Var = (s0) obj;
            if (this.a.equals(((H) s0Var).a)) {
                if (Arrays.equals(this.b, (s0Var instanceof H ? (H) s0Var : (H) s0Var).b)) {
                    return true;
                }
            }
        }
        return false;
    }

    public final int hashCode() {
        return ((this.a.hashCode() ^ 1000003) * 1000003) ^ Arrays.hashCode(this.b);
    }

    public final String toString() {
        return "File{filename=" + this.a + ", contents=" + Arrays.toString(this.b) + "}";
    }
}

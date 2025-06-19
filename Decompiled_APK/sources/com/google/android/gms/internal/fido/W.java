package com.google.android.gms.internal.fido;

import java.util.Arrays;

/* loaded from: classes2.dex */
public final class W extends b0 {
    public final boolean a;

    public W(boolean z) {
        this.a = z;
    }

    @Override // com.google.android.gms.internal.fido.b0
    public final int a() {
        return b0.d((byte) -32);
    }

    @Override // java.lang.Comparable
    public final /* bridge */ /* synthetic */ int compareTo(Object obj) {
        b0 b0Var = (b0) obj;
        int iA = b0Var.a();
        int iD = b0.d((byte) -32);
        if (iD != iA) {
            return iD - b0Var.a();
        }
        return (true != this.a ? 20 : 21) - (true != ((W) b0Var).a ? 20 : 21);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return obj != null && W.class == obj.getClass() && this.a == ((W) obj).a;
    }

    public final int hashCode() {
        return Arrays.hashCode(new Object[]{Integer.valueOf(b0.d((byte) -32)), Boolean.valueOf(this.a)});
    }

    public final String toString() {
        return Boolean.toString(this.a);
    }
}

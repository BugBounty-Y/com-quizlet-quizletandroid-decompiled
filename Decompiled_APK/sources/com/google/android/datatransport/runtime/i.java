package com.google.android.datatransport.runtime;

import android.util.Base64;
import java.util.Arrays;

/* loaded from: classes2.dex */
public final class i {
    public final String a;
    public final byte[] b;
    public final com.google.android.datatransport.d c;

    public i(String str, byte[] bArr, com.google.android.datatransport.d dVar) {
        this.a = str;
        this.b = bArr;
        this.c = dVar;
    }

    public static com.quizlet.data.repository.set.f a() {
        com.quizlet.data.repository.set.f fVar = new com.quizlet.data.repository.set.f(5);
        fVar.d = com.google.android.datatransport.d.a;
        return fVar;
    }

    public final i b(com.google.android.datatransport.d dVar) {
        com.quizlet.data.repository.set.f fVarA = a();
        fVarA.s(this.a);
        if (dVar == null) {
            throw new NullPointerException("Null priority");
        }
        fVarA.d = dVar;
        fVarA.c = this.b;
        return fVarA.b();
    }

    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj instanceof i) {
            i iVar = (i) obj;
            if (this.a.equals(iVar.a) && Arrays.equals(this.b, iVar.b) && this.c.equals(iVar.c)) {
                return true;
            }
        }
        return false;
    }

    public final int hashCode() {
        return ((((this.a.hashCode() ^ 1000003) * 1000003) ^ Arrays.hashCode(this.b)) * 1000003) ^ this.c.hashCode();
    }

    public final String toString() {
        byte[] bArr = this.b;
        return "TransportContext(" + this.a + ", " + this.c + ", " + (bArr == null ? "" : Base64.encodeToString(bArr, 2)) + ")";
    }
}

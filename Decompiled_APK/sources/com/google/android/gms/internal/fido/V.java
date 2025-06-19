package com.google.android.gms.internal.fido;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;

/* loaded from: classes2.dex */
public final class V extends b0 {
    public final C2959x a;
    public final int b;

    public V(C2959x c2959x) throws zzhf {
        c2959x.getClass();
        this.a = c2959x;
        int i = 0;
        int i2 = 0;
        while (true) {
            C2959x c2959x2 = this.a;
            if (i >= c2959x2.d) {
                break;
            }
            int iB = ((b0) c2959x2.get(i)).b();
            if (i2 < iB) {
                i2 = iB;
            }
            i++;
        }
        int i3 = i2 + 1;
        this.b = i3;
        if (i3 > 8) {
            throw new zzhf("Exceeded cutoff limit for max depth of cbor value");
        }
    }

    @Override // com.google.android.gms.internal.fido.b0
    public final int a() {
        return b0.d(Byte.MIN_VALUE);
    }

    @Override // com.google.android.gms.internal.fido.b0
    public final int b() {
        return this.b;
    }

    @Override // java.lang.Comparable
    public final int compareTo(Object obj) {
        b0 b0Var = (b0) obj;
        int iA = b0Var.a();
        int iD = b0.d(Byte.MIN_VALUE);
        if (iD != iA) {
            return iD - b0Var.a();
        }
        C2959x c2959x = this.a;
        int i = c2959x.d;
        C2959x c2959x2 = ((V) b0Var).a;
        int i2 = c2959x2.d;
        if (i != i2) {
            return i - i2;
        }
        for (int i3 = 0; i3 < c2959x.d; i3++) {
            int iCompareTo = ((b0) c2959x.get(i3)).compareTo((b0) c2959x2.get(i3));
            if (iCompareTo != 0) {
                return iCompareTo;
            }
        }
        return 0;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj != null && V.class == obj.getClass()) {
            return this.a.equals(((V) obj).a);
        }
        return false;
    }

    public final int hashCode() {
        return Arrays.hashCode(new Object[]{Integer.valueOf(b0.d(Byte.MIN_VALUE)), this.a});
    }

    public final String toString() {
        C2959x c2959x = this.a;
        if (c2959x.isEmpty()) {
            return "[]";
        }
        ArrayList arrayList = new ArrayList();
        for (int i = 0; i < c2959x.d; i++) {
            arrayList.add(((b0) c2959x.get(i)).toString().replace("\n", "\n  "));
        }
        StringBuilder sb = new StringBuilder("[\n  ");
        Iterator it2 = arrayList.iterator();
        try {
            if (it2.hasNext()) {
                sb.append(assistantMode.utils.studiableMetadata.b.b0(it2.next()));
                while (it2.hasNext()) {
                    sb.append((CharSequence) ",\n  ");
                    sb.append(assistantMode.utils.studiableMetadata.b.b0(it2.next()));
                }
            }
            sb.append("\n]");
            return sb.toString();
        } catch (IOException e) {
            throw new AssertionError(e);
        }
    }
}

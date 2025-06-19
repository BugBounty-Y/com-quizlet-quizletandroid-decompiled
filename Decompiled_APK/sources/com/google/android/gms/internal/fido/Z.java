package com.google.android.gms.internal.fido;

import java.io.IOException;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;

/* loaded from: classes2.dex */
public final class Z extends b0 {
    public final int a;
    public final r b;

    public Z(r rVar) throws zzhf {
        rVar.getClass();
        this.b = rVar;
        D dE = rVar.entrySet().e();
        int i = 0;
        while (dE.hasNext()) {
            Map.Entry entry = (Map.Entry) dE.next();
            int iB = ((b0) entry.getKey()).b();
            i = i < iB ? iB : i;
            int iB2 = ((b0) entry.getValue()).b();
            if (i < iB2) {
                i = iB2;
            }
        }
        int i2 = i + 1;
        this.a = i2;
        if (i2 > 8) {
            throw new zzhf("Exceeded cutoff limit for max depth of cbor value");
        }
    }

    @Override // com.google.android.gms.internal.fido.b0
    public final int a() {
        return b0.d((byte) -96);
    }

    @Override // com.google.android.gms.internal.fido.b0
    public final int b() {
        return this.a;
    }

    @Override // java.lang.Comparable
    public final int compareTo(Object obj) {
        int iCompareTo;
        b0 b0Var = (b0) obj;
        int iA = b0Var.a();
        int iD = b0.d((byte) -96);
        if (iD != iA) {
            return iD - b0Var.a();
        }
        r rVar = this.b;
        int size = rVar.d.size();
        r rVar2 = ((Z) b0Var).b;
        if (size != rVar2.d.size()) {
            return rVar.d.size() - rVar2.d.size();
        }
        D dE = rVar.entrySet().e();
        D dE2 = rVar2.entrySet().e();
        do {
            if (!dE.hasNext() && !dE2.hasNext()) {
                return 0;
            }
            Map.Entry entry = (Map.Entry) dE.next();
            Map.Entry entry2 = (Map.Entry) dE2.next();
            int iCompareTo2 = ((b0) entry.getKey()).compareTo((b0) entry2.getKey());
            if (iCompareTo2 != 0) {
                return iCompareTo2;
            }
            iCompareTo = ((b0) entry.getValue()).compareTo((b0) entry2.getValue());
        } while (iCompareTo == 0);
        return iCompareTo;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj != null && Z.class == obj.getClass()) {
            return this.b.equals(((Z) obj).b);
        }
        return false;
    }

    public final int hashCode() {
        return Arrays.hashCode(new Object[]{Integer.valueOf(b0.d((byte) -96)), this.b});
    }

    public final String toString() {
        r rVar = this.b;
        if (rVar.isEmpty()) {
            return "{}";
        }
        LinkedHashMap linkedHashMap = new LinkedHashMap();
        D dE = rVar.entrySet().e();
        while (dE.hasNext()) {
            Map.Entry entry = (Map.Entry) dE.next();
            linkedHashMap.put(((b0) entry.getKey()).toString().replace("\n", "\n  "), ((b0) entry.getValue()).toString().replace("\n", "\n  "));
        }
        assistantMode.utils.studiableMetadata.b bVar = new assistantMode.utils.studiableMetadata.b(10);
        StringBuilder sb = new StringBuilder("{\n  ");
        try {
            AbstractC2937a.g(sb, linkedHashMap.entrySet().iterator(), bVar);
            sb.append("\n}");
            return sb.toString();
        } catch (IOException e) {
            throw new AssertionError(e);
        }
    }
}

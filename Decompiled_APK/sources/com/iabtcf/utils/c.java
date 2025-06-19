package com.iabtcf.utils;

import java.util.BitSet;

/* loaded from: classes2.dex */
public final class c extends n {
    public static final c b = new c(new BitSet());
    public final BitSet a;

    public c(BitSet bitSet) {
        this.a = bitSet;
    }

    public final Object clone() {
        return new c((BitSet) this.a.clone());
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || c.class != obj.getClass()) {
            return false;
        }
        BitSet bitSet = ((c) obj).a;
        BitSet bitSet2 = this.a;
        return bitSet2 == null ? bitSet == null : bitSet2.equals(bitSet);
    }

    public final int hashCode() {
        BitSet bitSet = this.a;
        return 31 + (bitSet == null ? 0 : bitSet.hashCode());
    }

    public final String toString() {
        return this.a.toString();
    }
}

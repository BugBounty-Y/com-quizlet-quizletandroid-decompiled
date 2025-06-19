package com.google.android.gms.internal.play_billing;

/* loaded from: classes2.dex */
public final class O extends P {
    public static final O c = new O(C3838u.c, C3838u.b);
    public final AbstractC3841v a;
    public final AbstractC3841v b;

    public O(AbstractC3841v abstractC3841v, AbstractC3841v abstractC3841v2) {
        this.a = abstractC3841v;
        this.b = abstractC3841v2;
        if (abstractC3841v.a(abstractC3841v2) > 0 || abstractC3841v == C3838u.b || abstractC3841v2 == C3838u.c) {
            StringBuilder sb = new StringBuilder(16);
            abstractC3841v.b(sb);
            sb.append("..");
            abstractC3841v2.c(sb);
            throw new IllegalArgumentException("Invalid range: ".concat(sb.toString()));
        }
    }

    public final boolean equals(Object obj) {
        if (obj instanceof O) {
            O o = (O) obj;
            if (this.a.equals(o.a) && this.b.equals(o.b)) {
                return true;
            }
        }
        return false;
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder(16);
        this.a.b(sb);
        sb.append("..");
        this.b.c(sb);
        return sb.toString();
    }
}

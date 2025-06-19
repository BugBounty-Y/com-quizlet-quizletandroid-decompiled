package com.google.android.gms.internal.ads;

/* loaded from: classes2.dex */
public final class HF {
    public static final HF d = new HF(new J9[0]);
    public final int a;
    public final Bu b;
    public int c;

    static {
        String str = Yo.a;
        Integer.toString(0, 36);
    }

    public HF(J9... j9Arr) {
        this.b = AbstractC2330lu.o(j9Arr);
        this.a = j9Arr.length;
        int i = 0;
        while (i < this.b.d) {
            int i2 = i + 1;
            int i3 = i2;
            while (true) {
                Bu bu = this.b;
                if (i3 < bu.d) {
                    if (((J9) bu.get(i)).equals(this.b.get(i3))) {
                        AbstractC2096gb.A("TrackGroupArray", "", new IllegalArgumentException("Multiple identical TrackGroups added to one TrackGroupArray."));
                    }
                    i3++;
                }
            }
            i = i2;
        }
    }

    public final J9 a(int i) {
        return (J9) this.b.get(i);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || HF.class != obj.getClass()) {
            return false;
        }
        HF hf = (HF) obj;
        return this.a == hf.a && this.b.equals(hf.b);
    }

    public final int hashCode() {
        int i = this.c;
        if (i != 0) {
            return i;
        }
        int iHashCode = this.b.hashCode();
        this.c = iHashCode;
        return iHashCode;
    }

    public final String toString() {
        return this.b.toString();
    }
}

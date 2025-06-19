package com.quizlet.features.match.data;

import com.google.android.gms.internal.mlkit_vision_barcode.O6;

/* renamed from: com.quizlet.features.match.data.c, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4347c extends O6 {
    public final long b;
    public final int c;

    public C4347c(int i, long j) {
        this.b = j;
        this.c = i;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C4347c)) {
            return false;
        }
        C4347c c4347c = (C4347c) obj;
        return this.b == c4347c.b && this.c == c4347c.c;
    }

    public final int hashCode() {
        return Integer.hashCode(this.c) + (Long.hashCode(this.b) * 31);
    }

    public final String toString() {
        return "DiagramMatchData(locationId=" + this.b + ", cardIndex=" + this.c + ")";
    }
}

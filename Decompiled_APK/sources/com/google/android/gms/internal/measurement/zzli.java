package com.google.android.gms.internal.measurement;

import java.io.IOException;
import java.util.Locale;

/* loaded from: classes2.dex */
public final class zzli extends IOException {
    public zzli() {
        super("CodedOutputStream was writing to a flat byte array and ran out of space.");
    }

    /* JADX WARN: Illegal instructions before constructor call */
    public zzli(long j, long j2, int i, IndexOutOfBoundsException indexOutOfBoundsException) {
        Locale locale = Locale.US;
        StringBuilder sbT = androidx.compose.animation.d0.t(j, "Pos: ", ", limit: ");
        sbT.append(j2);
        sbT.append(", len: ");
        sbT.append(i);
        super("CodedOutputStream was writing to a flat byte array and ran out of space.: ".concat(sbT.toString()), indexOutOfBoundsException);
    }

    public zzli(IndexOutOfBoundsException indexOutOfBoundsException) {
        super("CodedOutputStream was writing to a flat byte array and ran out of space.", indexOutOfBoundsException);
    }
}

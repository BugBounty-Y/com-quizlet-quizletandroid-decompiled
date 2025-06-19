package com.google.android.gms.internal.ads;

/* loaded from: classes2.dex */
public final class zzqe extends Exception {
    public final int a;
    public final boolean b;

    /* JADX WARN: Illegal instructions before constructor call */
    public zzqe(int i, int i2, int i3, int i4, int i5, C1832aG c1832aG, boolean z, RuntimeException runtimeException) {
        String strValueOf = String.valueOf(c1832aG);
        StringBuilder sbW = android.support.v4.media.session.a.w("AudioTrack init failed ", i, " Config(", ", ", i2);
        sbW.append(i3);
        sbW.append(", ");
        sbW.append(i4);
        sbW.append(", ");
        sbW.append(i5);
        sbW.append(") ");
        sbW.append(strValueOf);
        sbW.append(true != z ? "" : " (recoverable)");
        super(sbW.toString(), runtimeException);
        this.a = i;
        this.b = z;
    }
}

package com.google.android.gms.internal.ads;

/* loaded from: classes2.dex */
public final class zztf extends Exception {
    public final String a;
    public final HE b;
    public final String c;

    public zztf(C1832aG c1832aG, zztq zztqVar, int i) {
        this("Decoder init failed: [" + i + "], " + c1832aG.toString(), zztqVar, c1832aG.m, null, android.support.v4.media.session.a.f(Math.abs(i), "androidx.media3.exoplayer.mediacodec.MediaCodecRenderer_neg_"));
    }

    public zztf(String str, Throwable th, String str2, HE he, String str3) {
        super(str, th);
        this.a = str2;
        this.b = he;
        this.c = str3;
    }
}

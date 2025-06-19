package com.google.android.gms.internal.ads;

import java.util.Locale;

/* loaded from: classes2.dex */
public final class QC {
    public int a;
    public int b;
    public int c;
    public int d;
    public int e;
    public int f;
    public int g;
    public int h;
    public int i;
    public int j;
    public long k;
    public int l;

    public final synchronized void a() {
    }

    public final String toString() {
        int i = this.a;
        int i2 = this.b;
        int i3 = this.c;
        int i4 = this.d;
        int i5 = this.e;
        int i6 = this.f;
        int i7 = this.g;
        int i8 = this.h;
        int i9 = this.i;
        int i10 = this.j;
        long j = this.k;
        int i11 = this.l;
        String str = Yo.a;
        Locale locale = Locale.US;
        StringBuilder sbW = android.support.v4.media.session.a.w("DecoderCounters {\n decoderInits=", i, ",\n decoderReleases=", "\n queuedInputBuffers=", i2);
        sbW.append(i3);
        sbW.append("\n skippedInputBuffers=");
        sbW.append(i4);
        sbW.append("\n renderedOutputBuffers=");
        sbW.append(i5);
        sbW.append("\n skippedOutputBuffers=");
        sbW.append(i6);
        sbW.append("\n droppedBuffers=");
        sbW.append(i7);
        sbW.append("\n droppedInputBuffers=");
        sbW.append(i8);
        sbW.append("\n maxConsecutiveDroppedBuffers=");
        sbW.append(i9);
        sbW.append("\n droppedToKeyframeEvents=");
        sbW.append(i10);
        sbW.append("\n totalVideoFrameProcessingOffsetUs=");
        sbW.append(j);
        sbW.append("\n videoFrameProcessingOffsetCount=");
        sbW.append(i11);
        sbW.append("\n}");
        return sbW.toString();
    }
}

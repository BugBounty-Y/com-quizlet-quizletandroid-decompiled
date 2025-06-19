package com.google.android.gms.internal.ads;

import android.media.AudioTimestamp;
import android.media.AudioTrack;
import java.nio.ByteBuffer;

/* renamed from: com.google.android.gms.internal.ads.r3, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2554r3 {
    public long a;
    public long b;
    public long c;
    public final Object d;
    public final Object e;

    public /* synthetic */ C2554r3(ByteBuffer byteBuffer, long j, long j2, long j3, ByteBuffer byteBuffer2) {
        this.d = byteBuffer;
        this.a = j;
        this.b = j2;
        this.c = j3;
        this.e = byteBuffer2;
    }

    public C2554r3(AudioTrack audioTrack) {
        this.d = audioTrack;
        this.e = new AudioTimestamp();
    }
}

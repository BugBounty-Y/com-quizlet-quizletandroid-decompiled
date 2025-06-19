package com.google.android.gms.internal.ads;

import android.media.AudioTrack;

/* renamed from: com.google.android.gms.internal.ads.jE, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2222jE {
    public final C2554r3 a;
    public int b;
    public long c;
    public long d;
    public long e;
    public long f;

    public C2222jE(AudioTrack audioTrack) {
        this.a = new C2554r3(audioTrack);
        a(0);
    }

    public final void a(int i) {
        this.b = i;
        long j = 10000;
        if (i == 0) {
            this.e = 0L;
            this.f = -1L;
            this.c = System.nanoTime() / 1000;
        } else {
            if (i == 1) {
                this.d = 10000L;
                return;
            }
            j = (i == 2 || i == 3) ? 10000000L : 500000L;
        }
        this.d = j;
    }
}

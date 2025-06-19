package com.google.android.gms.internal.ads;

import android.media.MediaCodec;
import android.media.MediaFormat;
import android.os.Bundle;
import android.view.Surface;
import java.nio.ByteBuffer;

/* loaded from: classes2.dex */
public interface GE {
    MediaFormat a();

    ByteBuffer d(int i);

    ByteBuffer e(int i);

    void f(Surface surface);

    boolean g(Lr lr);

    void h(int i, long j);

    void i();

    void j(int i);

    int k(MediaCodec.BufferInfo bufferInfo);

    void l();

    void m(int i);

    void n(long j, int i, int i2, int i3);

    void o(Bundle bundle);

    void p(int i, LC lc, long j);

    int zza();

    void zzi();
}

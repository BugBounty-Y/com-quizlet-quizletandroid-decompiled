package com.google.android.gms.internal.ads;

import java.nio.ByteBuffer;

/* loaded from: classes2.dex */
public abstract class Yx {
    public static final C2604sA a = C2604sA.a(new byte[0]);

    public static final C2604sA a(int i) {
        return C2604sA.a(ByteBuffer.allocate(5).put((byte) 0).putInt(i).array());
    }

    public static final C2604sA b(int i) {
        return C2604sA.a(ByteBuffer.allocate(5).put((byte) 1).putInt(i).array());
    }
}

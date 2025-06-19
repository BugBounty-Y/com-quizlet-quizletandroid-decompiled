package com.fasterxml.uuid.impl;

import java.util.UUID;

/* loaded from: classes.dex */
public abstract class a {
    static {
        new UUID(0L, 0L);
        new UUID(-1L, -1L);
    }

    public static final int a(int i, byte[] bArr) {
        return (bArr[i + 3] & 255) | (bArr[i] << 24) | ((bArr[i + 1] & 255) << 16) | ((bArr[i + 2] & 255) << 8);
    }
}

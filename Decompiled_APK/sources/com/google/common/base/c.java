package com.google.common.base;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

/* loaded from: classes2.dex */
public abstract class c {
    public static final Charset a;

    static {
        Charset charset = StandardCharsets.US_ASCII;
        Charset charset2 = StandardCharsets.ISO_8859_1;
        a = StandardCharsets.UTF_8;
        Charset charset3 = StandardCharsets.UTF_16BE;
        Charset charset4 = StandardCharsets.UTF_16LE;
        Charset charset5 = StandardCharsets.UTF_16;
    }
}

package io.ktor.util;

import kotlin.text.StringsKt;

/* loaded from: classes3.dex */
public abstract class b {
    public static final /* synthetic */ int a = 0;

    static {
        int[] iArr = new int[256];
        for (int i = 0; i < 256; i++) {
            iArr[i] = StringsKt.L("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", (char) i, 0, false, 6);
        }
    }
}

package com.sdk.growthbook.utils;

import kotlin.Metadata;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public interface Crypto {
    @NotNull
    byte[] decrypt(@NotNull byte[] bArr, @NotNull byte[] bArr2, @NotNull byte[] bArr3);

    @NotNull
    byte[] encrypt(@NotNull byte[] bArr, @NotNull byte[] bArr2, @NotNull byte[] bArr3);
}

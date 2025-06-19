package com.sdk.growthbook.sandbox;

import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.json.k;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public interface CachingLayer {

    @Metadata
    public static final class DefaultImpls {
        public static k getContent(@NotNull CachingLayer cachingLayer, @NotNull String fileName) {
            Intrinsics.checkNotNullParameter(fileName, "fileName");
            return null;
        }

        public static void saveContent(@NotNull CachingLayer cachingLayer, @NotNull String fileName, @NotNull k content) {
            Intrinsics.checkNotNullParameter(fileName, "fileName");
            Intrinsics.checkNotNullParameter(content, "content");
        }
    }

    k getContent(@NotNull String str);

    void saveContent(@NotNull String str, @NotNull k kVar);
}

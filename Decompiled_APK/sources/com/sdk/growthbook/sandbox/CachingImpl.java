package com.sdk.growthbook.sandbox;

import kotlin.Metadata;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class CachingImpl {

    @NotNull
    public static final CachingImpl INSTANCE = new CachingImpl();

    private CachingImpl() {
    }

    @NotNull
    public final CachingLayer getLayer() {
        return new CachingAndroid();
    }
}

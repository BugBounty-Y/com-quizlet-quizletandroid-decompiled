package com.skydoves.balloon.overlay;

import kotlin.Metadata;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class BalloonOverlayEmpty extends BalloonOverlayShape {

    @NotNull
    public static final BalloonOverlayEmpty INSTANCE = new BalloonOverlayEmpty();

    private BalloonOverlayEmpty() {
        super(null);
    }
}

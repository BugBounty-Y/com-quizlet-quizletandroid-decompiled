package com.skydoves.balloon.compose;

import com.skydoves.balloon.BalloonCenterAlign;
import kotlin.Metadata;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public interface AwaitBalloonWindowsDsl {

    @Metadata
    public static final class DefaultImpls {
        public static /* synthetic */ void alignBottom$default(AwaitBalloonWindowsDsl awaitBalloonWindowsDsl, BalloonWindow balloonWindow, int i, int i2, int i3, Object obj) {
            if (obj != null) {
                throw new UnsupportedOperationException("Super calls with default arguments not supported in this target, function: alignBottom");
            }
            if ((i3 & 1) != 0) {
                i = 0;
            }
            if ((i3 & 2) != 0) {
                i2 = 0;
            }
            awaitBalloonWindowsDsl.alignBottom(balloonWindow, i, i2);
        }

        public static /* synthetic */ void alignEnd$default(AwaitBalloonWindowsDsl awaitBalloonWindowsDsl, BalloonWindow balloonWindow, int i, int i2, int i3, Object obj) {
            if (obj != null) {
                throw new UnsupportedOperationException("Super calls with default arguments not supported in this target, function: alignEnd");
            }
            if ((i3 & 1) != 0) {
                i = 0;
            }
            if ((i3 & 2) != 0) {
                i2 = 0;
            }
            awaitBalloonWindowsDsl.alignEnd(balloonWindow, i, i2);
        }

        public static /* synthetic */ void alignStart$default(AwaitBalloonWindowsDsl awaitBalloonWindowsDsl, BalloonWindow balloonWindow, int i, int i2, int i3, Object obj) {
            if (obj != null) {
                throw new UnsupportedOperationException("Super calls with default arguments not supported in this target, function: alignStart");
            }
            if ((i3 & 1) != 0) {
                i = 0;
            }
            if ((i3 & 2) != 0) {
                i2 = 0;
            }
            awaitBalloonWindowsDsl.alignStart(balloonWindow, i, i2);
        }

        public static /* synthetic */ void alignTop$default(AwaitBalloonWindowsDsl awaitBalloonWindowsDsl, BalloonWindow balloonWindow, int i, int i2, int i3, Object obj) {
            if (obj != null) {
                throw new UnsupportedOperationException("Super calls with default arguments not supported in this target, function: alignTop");
            }
            if ((i3 & 1) != 0) {
                i = 0;
            }
            if ((i3 & 2) != 0) {
                i2 = 0;
            }
            awaitBalloonWindowsDsl.alignTop(balloonWindow, i, i2);
        }

        public static /* synthetic */ void asDropDown$default(AwaitBalloonWindowsDsl awaitBalloonWindowsDsl, BalloonWindow balloonWindow, int i, int i2, int i3, Object obj) {
            if (obj != null) {
                throw new UnsupportedOperationException("Super calls with default arguments not supported in this target, function: asDropDown");
            }
            if ((i3 & 1) != 0) {
                i = 0;
            }
            if ((i3 & 2) != 0) {
                i2 = 0;
            }
            awaitBalloonWindowsDsl.asDropDown(balloonWindow, i, i2);
        }

        public static /* synthetic */ void atCenter$default(AwaitBalloonWindowsDsl awaitBalloonWindowsDsl, BalloonWindow balloonWindow, int i, int i2, BalloonCenterAlign balloonCenterAlign, int i3, Object obj) {
            if (obj != null) {
                throw new UnsupportedOperationException("Super calls with default arguments not supported in this target, function: atCenter");
            }
            if ((i3 & 1) != 0) {
                i = 0;
            }
            if ((i3 & 2) != 0) {
                i2 = 0;
            }
            if ((i3 & 4) != 0) {
                balloonCenterAlign = BalloonCenterAlign.TOP;
            }
            awaitBalloonWindowsDsl.atCenter(balloonWindow, i, i2, balloonCenterAlign);
        }
    }

    void alignBottom(@NotNull BalloonWindow balloonWindow, int i, int i2);

    void alignEnd(@NotNull BalloonWindow balloonWindow, int i, int i2);

    void alignStart(@NotNull BalloonWindow balloonWindow, int i, int i2);

    void alignTop(@NotNull BalloonWindow balloonWindow, int i, int i2);

    void asDropDown(@NotNull BalloonWindow balloonWindow, int i, int i2);

    void atCenter(@NotNull BalloonWindow balloonWindow, int i, int i2, @NotNull BalloonCenterAlign balloonCenterAlign);

    boolean getDismissSequentially();

    void setDismissSequentially(boolean z);
}

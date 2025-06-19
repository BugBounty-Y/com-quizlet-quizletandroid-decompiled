package com.skydoves.balloon;

import android.view.View;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public interface AwaitBalloonsDsl {

    @Metadata
    public static final class DefaultImpls {
        public static void alignBottom(@NotNull AwaitBalloonsDsl awaitBalloonsDsl, @NotNull View receiver, @NotNull Balloon balloon, int i, int i2) {
            Intrinsics.checkNotNullParameter(receiver, "$receiver");
            Intrinsics.checkNotNullParameter(balloon, "balloon");
            awaitBalloonsDsl.alignBottom(balloon, receiver, i, i2);
        }

        public static /* synthetic */ void alignBottom$default(AwaitBalloonsDsl awaitBalloonsDsl, Balloon balloon, View view, int i, int i2, int i3, Object obj) {
            if (obj != null) {
                throw new UnsupportedOperationException("Super calls with default arguments not supported in this target, function: alignBottom");
            }
            if ((i3 & 2) != 0) {
                i = 0;
            }
            if ((i3 & 4) != 0) {
                i2 = 0;
            }
            awaitBalloonsDsl.alignBottom(balloon, view, i, i2);
        }

        public static void alignEnd(@NotNull AwaitBalloonsDsl awaitBalloonsDsl, @NotNull View receiver, @NotNull Balloon balloon, int i, int i2) {
            Intrinsics.checkNotNullParameter(receiver, "$receiver");
            Intrinsics.checkNotNullParameter(balloon, "balloon");
            awaitBalloonsDsl.alignEnd(balloon, receiver, i, i2);
        }

        public static /* synthetic */ void alignEnd$default(AwaitBalloonsDsl awaitBalloonsDsl, Balloon balloon, View view, int i, int i2, int i3, Object obj) {
            if (obj != null) {
                throw new UnsupportedOperationException("Super calls with default arguments not supported in this target, function: alignEnd");
            }
            if ((i3 & 2) != 0) {
                i = 0;
            }
            if ((i3 & 4) != 0) {
                i2 = 0;
            }
            awaitBalloonsDsl.alignEnd(balloon, view, i, i2);
        }

        public static void alignStart(@NotNull AwaitBalloonsDsl awaitBalloonsDsl, @NotNull View receiver, @NotNull Balloon balloon, int i, int i2) {
            Intrinsics.checkNotNullParameter(receiver, "$receiver");
            Intrinsics.checkNotNullParameter(balloon, "balloon");
            awaitBalloonsDsl.alignStart(balloon, receiver, i, i2);
        }

        public static /* synthetic */ void alignStart$default(AwaitBalloonsDsl awaitBalloonsDsl, Balloon balloon, View view, int i, int i2, int i3, Object obj) {
            if (obj != null) {
                throw new UnsupportedOperationException("Super calls with default arguments not supported in this target, function: alignStart");
            }
            if ((i3 & 2) != 0) {
                i = 0;
            }
            if ((i3 & 4) != 0) {
                i2 = 0;
            }
            awaitBalloonsDsl.alignStart(balloon, view, i, i2);
        }

        public static void alignTop(@NotNull AwaitBalloonsDsl awaitBalloonsDsl, @NotNull View receiver, @NotNull Balloon balloon, int i, int i2) {
            Intrinsics.checkNotNullParameter(receiver, "$receiver");
            Intrinsics.checkNotNullParameter(balloon, "balloon");
            awaitBalloonsDsl.alignTop(balloon, receiver, i, i2);
        }

        public static /* synthetic */ void alignTop$default(AwaitBalloonsDsl awaitBalloonsDsl, Balloon balloon, View view, int i, int i2, int i3, Object obj) {
            if (obj != null) {
                throw new UnsupportedOperationException("Super calls with default arguments not supported in this target, function: alignTop");
            }
            if ((i3 & 2) != 0) {
                i = 0;
            }
            if ((i3 & 4) != 0) {
                i2 = 0;
            }
            awaitBalloonsDsl.alignTop(balloon, view, i, i2);
        }

        public static void asDropDown(@NotNull AwaitBalloonsDsl awaitBalloonsDsl, @NotNull View receiver, @NotNull Balloon balloon, int i, int i2) {
            Intrinsics.checkNotNullParameter(receiver, "$receiver");
            Intrinsics.checkNotNullParameter(balloon, "balloon");
            awaitBalloonsDsl.asDropDown(balloon, receiver, i, i2);
        }

        public static /* synthetic */ void asDropDown$default(AwaitBalloonsDsl awaitBalloonsDsl, Balloon balloon, View view, int i, int i2, int i3, Object obj) {
            if (obj != null) {
                throw new UnsupportedOperationException("Super calls with default arguments not supported in this target, function: asDropDown");
            }
            if ((i3 & 2) != 0) {
                i = 0;
            }
            if ((i3 & 4) != 0) {
                i2 = 0;
            }
            awaitBalloonsDsl.asDropDown(balloon, view, i, i2);
        }

        public static void atCenter(@NotNull AwaitBalloonsDsl awaitBalloonsDsl, @NotNull View receiver, @NotNull Balloon balloon, int i, int i2, @NotNull BalloonCenterAlign centerAlign) {
            Intrinsics.checkNotNullParameter(receiver, "$receiver");
            Intrinsics.checkNotNullParameter(balloon, "balloon");
            Intrinsics.checkNotNullParameter(centerAlign, "centerAlign");
            awaitBalloonsDsl.atCenter(balloon, receiver, i, i2, centerAlign);
        }

        public static /* synthetic */ void atCenter$default(AwaitBalloonsDsl awaitBalloonsDsl, Balloon balloon, View view, int i, int i2, BalloonCenterAlign balloonCenterAlign, int i3, Object obj) {
            if (obj != null) {
                throw new UnsupportedOperationException("Super calls with default arguments not supported in this target, function: atCenter");
            }
            if ((i3 & 2) != 0) {
                i = 0;
            }
            if ((i3 & 4) != 0) {
                i2 = 0;
            }
            if ((i3 & 8) != 0) {
                balloonCenterAlign = BalloonCenterAlign.TOP;
            }
            awaitBalloonsDsl.atCenter(balloon, view, i, i2, balloonCenterAlign);
        }

        public static /* synthetic */ void alignBottom$default(AwaitBalloonsDsl awaitBalloonsDsl, View view, Balloon balloon, int i, int i2, int i3, Object obj) {
            if (obj != null) {
                throw new UnsupportedOperationException("Super calls with default arguments not supported in this target, function: alignBottom");
            }
            if ((i3 & 2) != 0) {
                i = 0;
            }
            if ((i3 & 4) != 0) {
                i2 = 0;
            }
            awaitBalloonsDsl.alignBottom(view, balloon, i, i2);
        }

        public static /* synthetic */ void alignEnd$default(AwaitBalloonsDsl awaitBalloonsDsl, View view, Balloon balloon, int i, int i2, int i3, Object obj) {
            if (obj != null) {
                throw new UnsupportedOperationException("Super calls with default arguments not supported in this target, function: alignEnd");
            }
            if ((i3 & 2) != 0) {
                i = 0;
            }
            if ((i3 & 4) != 0) {
                i2 = 0;
            }
            awaitBalloonsDsl.alignEnd(view, balloon, i, i2);
        }

        public static /* synthetic */ void alignStart$default(AwaitBalloonsDsl awaitBalloonsDsl, View view, Balloon balloon, int i, int i2, int i3, Object obj) {
            if (obj != null) {
                throw new UnsupportedOperationException("Super calls with default arguments not supported in this target, function: alignStart");
            }
            if ((i3 & 2) != 0) {
                i = 0;
            }
            if ((i3 & 4) != 0) {
                i2 = 0;
            }
            awaitBalloonsDsl.alignStart(view, balloon, i, i2);
        }

        public static /* synthetic */ void alignTop$default(AwaitBalloonsDsl awaitBalloonsDsl, View view, Balloon balloon, int i, int i2, int i3, Object obj) {
            if (obj != null) {
                throw new UnsupportedOperationException("Super calls with default arguments not supported in this target, function: alignTop");
            }
            if ((i3 & 2) != 0) {
                i = 0;
            }
            if ((i3 & 4) != 0) {
                i2 = 0;
            }
            awaitBalloonsDsl.alignTop(view, balloon, i, i2);
        }

        public static /* synthetic */ void asDropDown$default(AwaitBalloonsDsl awaitBalloonsDsl, View view, Balloon balloon, int i, int i2, int i3, Object obj) {
            if (obj != null) {
                throw new UnsupportedOperationException("Super calls with default arguments not supported in this target, function: asDropDown");
            }
            if ((i3 & 2) != 0) {
                i = 0;
            }
            if ((i3 & 4) != 0) {
                i2 = 0;
            }
            awaitBalloonsDsl.asDropDown(view, balloon, i, i2);
        }

        public static /* synthetic */ void atCenter$default(AwaitBalloonsDsl awaitBalloonsDsl, View view, Balloon balloon, int i, int i2, BalloonCenterAlign balloonCenterAlign, int i3, Object obj) {
            if (obj != null) {
                throw new UnsupportedOperationException("Super calls with default arguments not supported in this target, function: atCenter");
            }
            if ((i3 & 2) != 0) {
                i = 0;
            }
            if ((i3 & 4) != 0) {
                i2 = 0;
            }
            if ((i3 & 8) != 0) {
                balloonCenterAlign = BalloonCenterAlign.TOP;
            }
            awaitBalloonsDsl.atCenter(view, balloon, i, i2, balloonCenterAlign);
        }
    }

    void alignBottom(@NotNull View view, @NotNull Balloon balloon, int i, int i2);

    void alignBottom(@NotNull Balloon balloon, @NotNull View view, int i, int i2);

    void alignEnd(@NotNull View view, @NotNull Balloon balloon, int i, int i2);

    void alignEnd(@NotNull Balloon balloon, @NotNull View view, int i, int i2);

    void alignStart(@NotNull View view, @NotNull Balloon balloon, int i, int i2);

    void alignStart(@NotNull Balloon balloon, @NotNull View view, int i, int i2);

    void alignTop(@NotNull View view, @NotNull Balloon balloon, int i, int i2);

    void alignTop(@NotNull Balloon balloon, @NotNull View view, int i, int i2);

    void asDropDown(@NotNull View view, @NotNull Balloon balloon, int i, int i2);

    void asDropDown(@NotNull Balloon balloon, @NotNull View view, int i, int i2);

    void atCenter(@NotNull View view, @NotNull Balloon balloon, int i, int i2, @NotNull BalloonCenterAlign balloonCenterAlign);

    void atCenter(@NotNull Balloon balloon, @NotNull View view, int i, int i2, @NotNull BalloonCenterAlign balloonCenterAlign);

    boolean getDismissSequentially();

    void setDismissSequentially(boolean z);
}

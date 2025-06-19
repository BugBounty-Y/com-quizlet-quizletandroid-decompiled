package com.skydoves.balloon.compose;

import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import com.skydoves.balloon.Balloon;
import com.skydoves.balloon.BalloonAlign;
import com.skydoves.balloon.BalloonCenterAlign;
import com.skydoves.balloon.OnBalloonClickListener;
import com.skydoves.balloon.OnBalloonDismissListener;
import com.skydoves.balloon.OnBalloonInitializedListener;
import com.skydoves.balloon.OnBalloonOutsideTouchListener;
import com.skydoves.balloon.OnBalloonOverlayClickListener;
import com.skydoves.balloon.annotations.InternalBalloonApi;
import java.util.List;
import kotlin.InterfaceC4935d;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.collections.K;
import kotlin.coroutines.h;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public interface BalloonWindow {

    @Metadata
    public static final class DefaultImpls {
        public static Object awaitAlign$default(BalloonWindow balloonWindow, BalloonAlign balloonAlign, View view, List list, int i, int i2, h hVar, int i3, Object obj) {
            if (obj != null) {
                throw new UnsupportedOperationException("Super calls with default arguments not supported in this target, function: awaitAlign");
            }
            if ((i3 & 4) != 0) {
                list = K.a;
            }
            return balloonWindow.awaitAlign(balloonAlign, view, list, (i3 & 8) != 0 ? 0 : i, (i3 & 16) != 0 ? 0 : i2, hVar);
        }

        public static /* synthetic */ Object awaitAlignBottom$default(BalloonWindow balloonWindow, int i, int i2, h hVar, int i3, Object obj) {
            if (obj != null) {
                throw new UnsupportedOperationException("Super calls with default arguments not supported in this target, function: awaitAlignBottom");
            }
            if ((i3 & 1) != 0) {
                i = 0;
            }
            if ((i3 & 2) != 0) {
                i2 = 0;
            }
            return balloonWindow.awaitAlignBottom(i, i2, hVar);
        }

        public static /* synthetic */ Object awaitAlignEnd$default(BalloonWindow balloonWindow, int i, int i2, h hVar, int i3, Object obj) {
            if (obj != null) {
                throw new UnsupportedOperationException("Super calls with default arguments not supported in this target, function: awaitAlignEnd");
            }
            if ((i3 & 1) != 0) {
                i = 0;
            }
            if ((i3 & 2) != 0) {
                i2 = 0;
            }
            return balloonWindow.awaitAlignEnd(i, i2, hVar);
        }

        public static /* synthetic */ Object awaitAlignStart$default(BalloonWindow balloonWindow, int i, int i2, h hVar, int i3, Object obj) {
            if (obj != null) {
                throw new UnsupportedOperationException("Super calls with default arguments not supported in this target, function: awaitAlignStart");
            }
            if ((i3 & 1) != 0) {
                i = 0;
            }
            if ((i3 & 2) != 0) {
                i2 = 0;
            }
            return balloonWindow.awaitAlignStart(i, i2, hVar);
        }

        public static /* synthetic */ Object awaitAlignTop$default(BalloonWindow balloonWindow, int i, int i2, h hVar, int i3, Object obj) {
            if (obj != null) {
                throw new UnsupportedOperationException("Super calls with default arguments not supported in this target, function: awaitAlignTop");
            }
            if ((i3 & 1) != 0) {
                i = 0;
            }
            if ((i3 & 2) != 0) {
                i2 = 0;
            }
            return balloonWindow.awaitAlignTop(i, i2, hVar);
        }

        public static /* synthetic */ Object awaitAsDropDown$default(BalloonWindow balloonWindow, int i, int i2, h hVar, int i3, Object obj) {
            if (obj != null) {
                throw new UnsupportedOperationException("Super calls with default arguments not supported in this target, function: awaitAsDropDown");
            }
            if ((i3 & 1) != 0) {
                i = 0;
            }
            if ((i3 & 2) != 0) {
                i2 = 0;
            }
            return balloonWindow.awaitAsDropDown(i, i2, hVar);
        }

        public static /* synthetic */ Object awaitAtCenter$default(BalloonWindow balloonWindow, int i, int i2, BalloonCenterAlign balloonCenterAlign, h hVar, int i3, Object obj) {
            if (obj != null) {
                throw new UnsupportedOperationException("Super calls with default arguments not supported in this target, function: awaitAtCenter");
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
            return balloonWindow.awaitAtCenter(i, i2, balloonCenterAlign, hVar);
        }

        public static /* synthetic */ Balloon relayShowAlign$default(BalloonWindow balloonWindow, BalloonAlign balloonAlign, Balloon balloon, int i, int i2, int i3, Object obj) {
            if (obj != null) {
                throw new UnsupportedOperationException("Super calls with default arguments not supported in this target, function: relayShowAlign");
            }
            if ((i3 & 4) != 0) {
                i = 0;
            }
            if ((i3 & 8) != 0) {
                i2 = 0;
            }
            return balloonWindow.relayShowAlign(balloonAlign, balloon, i, i2);
        }

        public static /* synthetic */ Balloon relayShowAlignBottom$default(BalloonWindow balloonWindow, Balloon balloon, int i, int i2, int i3, Object obj) {
            if (obj != null) {
                throw new UnsupportedOperationException("Super calls with default arguments not supported in this target, function: relayShowAlignBottom");
            }
            if ((i3 & 2) != 0) {
                i = 0;
            }
            if ((i3 & 4) != 0) {
                i2 = 0;
            }
            return balloonWindow.relayShowAlignBottom(balloon, i, i2);
        }

        public static /* synthetic */ Balloon relayShowAlignEnd$default(BalloonWindow balloonWindow, Balloon balloon, int i, int i2, int i3, Object obj) {
            if (obj != null) {
                throw new UnsupportedOperationException("Super calls with default arguments not supported in this target, function: relayShowAlignEnd");
            }
            if ((i3 & 2) != 0) {
                i = 0;
            }
            if ((i3 & 4) != 0) {
                i2 = 0;
            }
            return balloonWindow.relayShowAlignEnd(balloon, i, i2);
        }

        public static /* synthetic */ Balloon relayShowAlignLeft$default(BalloonWindow balloonWindow, Balloon balloon, int i, int i2, int i3, Object obj) {
            if (obj != null) {
                throw new UnsupportedOperationException("Super calls with default arguments not supported in this target, function: relayShowAlignLeft");
            }
            if ((i3 & 2) != 0) {
                i = 0;
            }
            if ((i3 & 4) != 0) {
                i2 = 0;
            }
            return balloonWindow.relayShowAlignLeft(balloon, i, i2);
        }

        public static /* synthetic */ Balloon relayShowAlignRight$default(BalloonWindow balloonWindow, Balloon balloon, int i, int i2, int i3, Object obj) {
            if (obj != null) {
                throw new UnsupportedOperationException("Super calls with default arguments not supported in this target, function: relayShowAlignRight");
            }
            if ((i3 & 2) != 0) {
                i = 0;
            }
            if ((i3 & 4) != 0) {
                i2 = 0;
            }
            return balloonWindow.relayShowAlignRight(balloon, i, i2);
        }

        public static /* synthetic */ Balloon relayShowAlignStart$default(BalloonWindow balloonWindow, Balloon balloon, int i, int i2, int i3, Object obj) {
            if (obj != null) {
                throw new UnsupportedOperationException("Super calls with default arguments not supported in this target, function: relayShowAlignStart");
            }
            if ((i3 & 2) != 0) {
                i = 0;
            }
            if ((i3 & 4) != 0) {
                i2 = 0;
            }
            return balloonWindow.relayShowAlignStart(balloon, i, i2);
        }

        public static /* synthetic */ Balloon relayShowAlignTop$default(BalloonWindow balloonWindow, Balloon balloon, int i, int i2, int i3, Object obj) {
            if (obj != null) {
                throw new UnsupportedOperationException("Super calls with default arguments not supported in this target, function: relayShowAlignTop");
            }
            if ((i3 & 2) != 0) {
                i = 0;
            }
            if ((i3 & 4) != 0) {
                i2 = 0;
            }
            return balloonWindow.relayShowAlignTop(balloon, i, i2);
        }

        public static /* synthetic */ Balloon relayShowAsDropDown$default(BalloonWindow balloonWindow, Balloon balloon, int i, int i2, int i3, Object obj) {
            if (obj != null) {
                throw new UnsupportedOperationException("Super calls with default arguments not supported in this target, function: relayShowAsDropDown");
            }
            if ((i3 & 2) != 0) {
                i = 0;
            }
            if ((i3 & 4) != 0) {
                i2 = 0;
            }
            return balloonWindow.relayShowAsDropDown(balloon, i, i2);
        }

        public static /* synthetic */ Balloon relayShowAtCenter$default(BalloonWindow balloonWindow, Balloon balloon, int i, int i2, BalloonCenterAlign balloonCenterAlign, int i3, Object obj) {
            if (obj != null) {
                throw new UnsupportedOperationException("Super calls with default arguments not supported in this target, function: relayShowAtCenter");
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
            return balloonWindow.relayShowAtCenter(balloon, i, i2, balloonCenterAlign);
        }

        public static void showAlign$default(BalloonWindow balloonWindow, BalloonAlign balloonAlign, View view, List list, int i, int i2, int i3, Object obj) {
            if (obj != null) {
                throw new UnsupportedOperationException("Super calls with default arguments not supported in this target, function: showAlign");
            }
            if ((i3 & 4) != 0) {
                list = K.a;
            }
            balloonWindow.showAlign(balloonAlign, view, list, (i3 & 8) != 0 ? 0 : i, (i3 & 16) != 0 ? 0 : i2);
        }

        public static /* synthetic */ void showAlignBottom$default(BalloonWindow balloonWindow, int i, int i2, int i3, Object obj) {
            if (obj != null) {
                throw new UnsupportedOperationException("Super calls with default arguments not supported in this target, function: showAlignBottom");
            }
            if ((i3 & 1) != 0) {
                i = 0;
            }
            if ((i3 & 2) != 0) {
                i2 = 0;
            }
            balloonWindow.showAlignBottom(i, i2);
        }

        public static /* synthetic */ void showAlignEnd$default(BalloonWindow balloonWindow, int i, int i2, int i3, Object obj) {
            if (obj != null) {
                throw new UnsupportedOperationException("Super calls with default arguments not supported in this target, function: showAlignEnd");
            }
            if ((i3 & 1) != 0) {
                i = 0;
            }
            if ((i3 & 2) != 0) {
                i2 = 0;
            }
            balloonWindow.showAlignEnd(i, i2);
        }

        public static /* synthetic */ void showAlignLeft$default(BalloonWindow balloonWindow, int i, int i2, int i3, Object obj) {
            if (obj != null) {
                throw new UnsupportedOperationException("Super calls with default arguments not supported in this target, function: showAlignLeft");
            }
            if ((i3 & 1) != 0) {
                i = 0;
            }
            if ((i3 & 2) != 0) {
                i2 = 0;
            }
            balloonWindow.showAlignLeft(i, i2);
        }

        public static /* synthetic */ void showAlignRight$default(BalloonWindow balloonWindow, int i, int i2, int i3, Object obj) {
            if (obj != null) {
                throw new UnsupportedOperationException("Super calls with default arguments not supported in this target, function: showAlignRight");
            }
            if ((i3 & 1) != 0) {
                i = 0;
            }
            if ((i3 & 2) != 0) {
                i2 = 0;
            }
            balloonWindow.showAlignRight(i, i2);
        }

        public static /* synthetic */ void showAlignStart$default(BalloonWindow balloonWindow, int i, int i2, int i3, Object obj) {
            if (obj != null) {
                throw new UnsupportedOperationException("Super calls with default arguments not supported in this target, function: showAlignStart");
            }
            if ((i3 & 1) != 0) {
                i = 0;
            }
            if ((i3 & 2) != 0) {
                i2 = 0;
            }
            balloonWindow.showAlignStart(i, i2);
        }

        public static /* synthetic */ void showAlignTop$default(BalloonWindow balloonWindow, int i, int i2, int i3, Object obj) {
            if (obj != null) {
                throw new UnsupportedOperationException("Super calls with default arguments not supported in this target, function: showAlignTop");
            }
            if ((i3 & 1) != 0) {
                i = 0;
            }
            if ((i3 & 2) != 0) {
                i2 = 0;
            }
            balloonWindow.showAlignTop(i, i2);
        }

        public static /* synthetic */ void showAsDropDown$default(BalloonWindow balloonWindow, int i, int i2, int i3, Object obj) {
            if (obj != null) {
                throw new UnsupportedOperationException("Super calls with default arguments not supported in this target, function: showAsDropDown");
            }
            if ((i3 & 1) != 0) {
                i = 0;
            }
            if ((i3 & 2) != 0) {
                i2 = 0;
            }
            balloonWindow.showAsDropDown(i, i2);
        }

        public static /* synthetic */ void showAtCenter$default(BalloonWindow balloonWindow, int i, int i2, BalloonCenterAlign balloonCenterAlign, int i3, Object obj) {
            if (obj != null) {
                throw new UnsupportedOperationException("Super calls with default arguments not supported in this target, function: showAtCenter");
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
            balloonWindow.showAtCenter(i, i2, balloonCenterAlign);
        }

        public static /* synthetic */ void update$default(BalloonWindow balloonWindow, int i, int i2, int i3, Object obj) {
            if (obj != null) {
                throw new UnsupportedOperationException("Super calls with default arguments not supported in this target, function: update");
            }
            if ((i3 & 1) != 0) {
                i = 0;
            }
            if ((i3 & 2) != 0) {
                i2 = 0;
            }
            balloonWindow.update(i, i2);
        }

        public static /* synthetic */ void updateAlign$default(BalloonWindow balloonWindow, BalloonAlign balloonAlign, int i, int i2, int i3, Object obj) {
            if (obj != null) {
                throw new UnsupportedOperationException("Super calls with default arguments not supported in this target, function: updateAlign");
            }
            if ((i3 & 2) != 0) {
                i = 0;
            }
            if ((i3 & 4) != 0) {
                i2 = 0;
            }
            balloonWindow.updateAlign(balloonAlign, i, i2);
        }

        public static /* synthetic */ void updateAlignBottom$default(BalloonWindow balloonWindow, int i, int i2, int i3, Object obj) {
            if (obj != null) {
                throw new UnsupportedOperationException("Super calls with default arguments not supported in this target, function: updateAlignBottom");
            }
            if ((i3 & 1) != 0) {
                i = 0;
            }
            if ((i3 & 2) != 0) {
                i2 = 0;
            }
            balloonWindow.updateAlignBottom(i, i2);
        }

        public static /* synthetic */ void updateAlignEnd$default(BalloonWindow balloonWindow, int i, int i2, int i3, Object obj) {
            if (obj != null) {
                throw new UnsupportedOperationException("Super calls with default arguments not supported in this target, function: updateAlignEnd");
            }
            if ((i3 & 1) != 0) {
                i = 0;
            }
            if ((i3 & 2) != 0) {
                i2 = 0;
            }
            balloonWindow.updateAlignEnd(i, i2);
        }

        public static /* synthetic */ void updateAlignStart$default(BalloonWindow balloonWindow, int i, int i2, int i3, Object obj) {
            if (obj != null) {
                throw new UnsupportedOperationException("Super calls with default arguments not supported in this target, function: updateAlignStart");
            }
            if ((i3 & 1) != 0) {
                i = 0;
            }
            if ((i3 & 2) != 0) {
                i2 = 0;
            }
            balloonWindow.updateAlignStart(i, i2);
        }

        public static /* synthetic */ void updateAlignTop$default(BalloonWindow balloonWindow, int i, int i2, int i3, Object obj) {
            if (obj != null) {
                throw new UnsupportedOperationException("Super calls with default arguments not supported in this target, function: updateAlignTop");
            }
            if ((i3 & 1) != 0) {
                i = 0;
            }
            if ((i3 & 2) != 0) {
                i2 = 0;
            }
            balloonWindow.updateAlignTop(i, i2);
        }
    }

    Object awaitAlign(@NotNull BalloonAlign balloonAlign, @NotNull View view, @NotNull List<? extends View> list, int i, int i2, @NotNull h<? super Unit> hVar);

    Object awaitAlignBottom(int i, int i2, @NotNull h<? super Unit> hVar);

    Object awaitAlignEnd(int i, int i2, @NotNull h<? super Unit> hVar);

    Object awaitAlignStart(int i, int i2, @NotNull h<? super Unit> hVar);

    Object awaitAlignTop(int i, int i2, @NotNull h<? super Unit> hVar);

    Object awaitAsDropDown(int i, int i2, @NotNull h<? super Unit> hVar);

    Object awaitAtCenter(int i, int i2, @NotNull BalloonCenterAlign balloonCenterAlign, @NotNull h<? super Unit> hVar);

    void clearAllPreferences();

    void dismiss();

    boolean dismissWithDelay(long j);

    @NotNull
    View getAnchorView();

    @NotNull
    Balloon getBalloon();

    @NotNull
    View getBalloonArrowView();

    @NotNull
    ViewGroup getContentView();

    int getMeasuredHeight();

    int getMeasuredWidth();

    @NotNull
    Balloon relayShowAlign(@NotNull BalloonAlign balloonAlign, @NotNull Balloon balloon, int i, int i2);

    @NotNull
    Balloon relayShowAlignBottom(@NotNull Balloon balloon, int i, int i2);

    @NotNull
    Balloon relayShowAlignEnd(@NotNull Balloon balloon, int i, int i2);

    @InterfaceC4935d
    @NotNull
    Balloon relayShowAlignLeft(@NotNull Balloon balloon, int i, int i2);

    @InterfaceC4935d
    @NotNull
    Balloon relayShowAlignRight(@NotNull Balloon balloon, int i, int i2);

    @NotNull
    Balloon relayShowAlignStart(@NotNull Balloon balloon, int i, int i2);

    @NotNull
    Balloon relayShowAlignTop(@NotNull Balloon balloon, int i, int i2);

    @NotNull
    Balloon relayShowAsDropDown(@NotNull Balloon balloon, int i, int i2);

    @NotNull
    Balloon relayShowAtCenter(@NotNull Balloon balloon, int i, int i2, @NotNull BalloonCenterAlign balloonCenterAlign);

    @NotNull
    Balloon setIsAttachedInDecor(boolean z);

    void setOnBalloonClickListener(OnBalloonClickListener onBalloonClickListener);

    /* synthetic */ void setOnBalloonClickListener(Function1 function1);

    void setOnBalloonDismissListener(OnBalloonDismissListener onBalloonDismissListener);

    /* synthetic */ void setOnBalloonDismissListener(Function0 function0);

    void setOnBalloonInitializedListener(OnBalloonInitializedListener onBalloonInitializedListener);

    /* synthetic */ void setOnBalloonInitializedListener(Function1 function1);

    void setOnBalloonOutsideTouchListener(OnBalloonOutsideTouchListener onBalloonOutsideTouchListener);

    /* synthetic */ void setOnBalloonOutsideTouchListener(Function2 function2);

    void setOnBalloonOverlayClickListener(OnBalloonOverlayClickListener onBalloonOverlayClickListener);

    /* synthetic */ void setOnBalloonOverlayClickListener(Function0 function0);

    void setOnBalloonOverlayTouchListener(View.OnTouchListener onTouchListener);

    void setOnBalloonOverlayTouchListener(@NotNull Function2<? super View, ? super MotionEvent, Boolean> function2);

    void setOnBalloonTouchListener(View.OnTouchListener onTouchListener);

    boolean shouldShowUp();

    void showAlign(@NotNull BalloonAlign balloonAlign, @NotNull View view, @NotNull List<? extends View> list, int i, int i2);

    void showAlignBottom(int i, int i2);

    void showAlignEnd(int i, int i2);

    @InterfaceC4935d
    void showAlignLeft(int i, int i2);

    @InterfaceC4935d
    void showAlignRight(int i, int i2);

    void showAlignStart(int i, int i2);

    void showAlignTop(int i, int i2);

    void showAsDropDown(int i, int i2);

    void showAtCenter(int i, int i2, @NotNull BalloonCenterAlign balloonCenterAlign);

    void update(int i, int i2);

    void updateAlign(@NotNull BalloonAlign balloonAlign, int i, int i2);

    void updateAlignBottom(int i, int i2);

    void updateAlignEnd(int i, int i2);

    void updateAlignStart(int i, int i2);

    void updateAlignTop(int i, int i2);

    @InternalBalloonApi
    void updateSizeOfBalloonCard(int i, int i2);
}

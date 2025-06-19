package com.skydoves.balloon;

import android.view.View;
import java.util.List;
import kotlin.InterfaceC4935d;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.collections.K;
import kotlin.coroutines.h;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class BalloonExtensionKt {
    public static final Object awaitAlign(@NotNull View view, @NotNull Balloon balloon, @NotNull BalloonAlign balloonAlign, @NotNull List<? extends View> list, int i, int i2, @NotNull h<? super Unit> hVar) {
        Object objAwaitAlign = balloon.awaitAlign(balloonAlign, view, list, i, i2, hVar);
        return objAwaitAlign == kotlin.coroutines.intrinsics.a.a ? objAwaitAlign : Unit.a;
    }

    public static Object awaitAlign$default(View view, Balloon balloon, BalloonAlign balloonAlign, List list, int i, int i2, h hVar, int i3, Object obj) {
        if ((i3 & 4) != 0) {
            list = K.a;
        }
        return awaitAlign(view, balloon, balloonAlign, list, (i3 & 8) != 0 ? 0 : i, (i3 & 16) != 0 ? 0 : i2, hVar);
    }

    public static final Object awaitAlignBottom(@NotNull View view, @NotNull Balloon balloon, int i, int i2, @NotNull h<? super Unit> hVar) {
        Object objAwaitAlignBottom = balloon.awaitAlignBottom(view, i, i2, hVar);
        return objAwaitAlignBottom == kotlin.coroutines.intrinsics.a.a ? objAwaitAlignBottom : Unit.a;
    }

    public static /* synthetic */ Object awaitAlignBottom$default(View view, Balloon balloon, int i, int i2, h hVar, int i3, Object obj) {
        if ((i3 & 2) != 0) {
            i = 0;
        }
        if ((i3 & 4) != 0) {
            i2 = 0;
        }
        return awaitAlignBottom(view, balloon, i, i2, hVar);
    }

    public static final Object awaitAlignEnd(@NotNull View view, @NotNull Balloon balloon, int i, int i2, @NotNull h<? super Unit> hVar) {
        Object objAwaitAlignEnd = balloon.awaitAlignEnd(view, i, i2, hVar);
        return objAwaitAlignEnd == kotlin.coroutines.intrinsics.a.a ? objAwaitAlignEnd : Unit.a;
    }

    public static /* synthetic */ Object awaitAlignEnd$default(View view, Balloon balloon, int i, int i2, h hVar, int i3, Object obj) {
        if ((i3 & 2) != 0) {
            i = 0;
        }
        if ((i3 & 4) != 0) {
            i2 = 0;
        }
        return awaitAlignEnd(view, balloon, i, i2, hVar);
    }

    public static final Object awaitAlignStart(@NotNull View view, @NotNull Balloon balloon, int i, int i2, @NotNull h<? super Unit> hVar) {
        Object objAwaitAlignStart = balloon.awaitAlignStart(view, i, i2, hVar);
        return objAwaitAlignStart == kotlin.coroutines.intrinsics.a.a ? objAwaitAlignStart : Unit.a;
    }

    public static /* synthetic */ Object awaitAlignStart$default(View view, Balloon balloon, int i, int i2, h hVar, int i3, Object obj) {
        if ((i3 & 2) != 0) {
            i = 0;
        }
        if ((i3 & 4) != 0) {
            i2 = 0;
        }
        return awaitAlignStart(view, balloon, i, i2, hVar);
    }

    public static final Object awaitAlignTop(@NotNull View view, @NotNull Balloon balloon, int i, int i2, @NotNull h<? super Unit> hVar) {
        Object objAwaitAlignTop = balloon.awaitAlignTop(view, i, i2, hVar);
        return objAwaitAlignTop == kotlin.coroutines.intrinsics.a.a ? objAwaitAlignTop : Unit.a;
    }

    public static /* synthetic */ Object awaitAlignTop$default(View view, Balloon balloon, int i, int i2, h hVar, int i3, Object obj) {
        if ((i3 & 2) != 0) {
            i = 0;
        }
        if ((i3 & 4) != 0) {
            i2 = 0;
        }
        return awaitAlignTop(view, balloon, i, i2, hVar);
    }

    public static final Object awaitAsDropDown(@NotNull View view, @NotNull Balloon balloon, int i, int i2, @NotNull h<? super Unit> hVar) {
        Object objAwaitAsDropDown = balloon.awaitAsDropDown(view, i, i2, hVar);
        return objAwaitAsDropDown == kotlin.coroutines.intrinsics.a.a ? objAwaitAsDropDown : Unit.a;
    }

    public static /* synthetic */ Object awaitAsDropDown$default(View view, Balloon balloon, int i, int i2, h hVar, int i3, Object obj) {
        if ((i3 & 2) != 0) {
            i = 0;
        }
        if ((i3 & 4) != 0) {
            i2 = 0;
        }
        return awaitAsDropDown(view, balloon, i, i2, hVar);
    }

    public static final Object awaitAtCenter(@NotNull View view, @NotNull Balloon balloon, int i, int i2, @NotNull BalloonCenterAlign balloonCenterAlign, @NotNull h<? super Unit> hVar) {
        Object objAwaitAtCenter = balloon.awaitAtCenter(view, i, i2, balloonCenterAlign, hVar);
        return objAwaitAtCenter == kotlin.coroutines.intrinsics.a.a ? objAwaitAtCenter : Unit.a;
    }

    public static /* synthetic */ Object awaitAtCenter$default(View view, Balloon balloon, int i, int i2, BalloonCenterAlign balloonCenterAlign, h hVar, int i3, Object obj) {
        if ((i3 & 2) != 0) {
            i = 0;
        }
        if ((i3 & 4) != 0) {
            i2 = 0;
        }
        if ((i3 & 8) != 0) {
            balloonCenterAlign = BalloonCenterAlign.TOP;
        }
        return awaitAtCenter(view, balloon, i, i2, balloonCenterAlign, hVar);
    }

    public static final /* synthetic */ void balloon(View view, final Function0<Unit> block) {
        Intrinsics.checkNotNullParameter(view, "<this>");
        Intrinsics.checkNotNullParameter(block, "block");
        view.post(new Runnable() { // from class: com.skydoves.balloon.BalloonExtensionKt.balloon.1
            @Override // java.lang.Runnable
            public final void run() {
                block.invoke();
            }
        });
    }

    public static final /* synthetic */ void showAlign(View view, Balloon balloon, BalloonAlign align) {
        Intrinsics.checkNotNullParameter(view, "<this>");
        Intrinsics.checkNotNullParameter(balloon, "balloon");
        Intrinsics.checkNotNullParameter(align, "align");
        showAlign$default(view, balloon, align, null, 0, 0, 28, null);
    }

    public static void showAlign$default(View view, Balloon balloon, BalloonAlign balloonAlign, List list, int i, int i2, int i3, Object obj) {
        if ((i3 & 4) != 0) {
            list = K.a;
        }
        showAlign(view, balloon, balloonAlign, list, (i3 & 8) != 0 ? 0 : i, (i3 & 16) != 0 ? 0 : i2);
    }

    public static final /* synthetic */ void showAlignBottom(View view, Balloon balloon) {
        Intrinsics.checkNotNullParameter(view, "<this>");
        Intrinsics.checkNotNullParameter(balloon, "balloon");
        showAlignBottom$default(view, balloon, 0, 0, 6, null);
    }

    public static /* synthetic */ void showAlignBottom$default(View view, Balloon balloon, int i, int i2, int i3, Object obj) {
        if ((i3 & 2) != 0) {
            i = 0;
        }
        if ((i3 & 4) != 0) {
            i2 = 0;
        }
        showAlignBottom(view, balloon, i, i2);
    }

    public static final /* synthetic */ void showAlignEnd(View view, Balloon balloon) {
        Intrinsics.checkNotNullParameter(view, "<this>");
        Intrinsics.checkNotNullParameter(balloon, "balloon");
        showAlignEnd$default(view, balloon, 0, 0, 6, null);
    }

    public static /* synthetic */ void showAlignEnd$default(View view, Balloon balloon, int i, int i2, int i3, Object obj) {
        if ((i3 & 2) != 0) {
            i = 0;
        }
        if ((i3 & 4) != 0) {
            i2 = 0;
        }
        showAlignEnd(view, balloon, i, i2);
    }

    @InterfaceC4935d
    public static final /* synthetic */ void showAlignLeft(View view, Balloon balloon) {
        Intrinsics.checkNotNullParameter(view, "<this>");
        Intrinsics.checkNotNullParameter(balloon, "balloon");
        showAlignLeft$default(view, balloon, 0, 0, 6, null);
    }

    public static /* synthetic */ void showAlignLeft$default(View view, Balloon balloon, int i, int i2, int i3, Object obj) {
        if ((i3 & 2) != 0) {
            i = 0;
        }
        if ((i3 & 4) != 0) {
            i2 = 0;
        }
        showAlignLeft(view, balloon, i, i2);
    }

    @InterfaceC4935d
    public static final /* synthetic */ void showAlignRight(View view, Balloon balloon) {
        Intrinsics.checkNotNullParameter(view, "<this>");
        Intrinsics.checkNotNullParameter(balloon, "balloon");
        showAlignRight$default(view, balloon, 0, 0, 6, null);
    }

    public static /* synthetic */ void showAlignRight$default(View view, Balloon balloon, int i, int i2, int i3, Object obj) {
        if ((i3 & 2) != 0) {
            i = 0;
        }
        if ((i3 & 4) != 0) {
            i2 = 0;
        }
        showAlignRight(view, balloon, i, i2);
    }

    public static final /* synthetic */ void showAlignStart(View view, Balloon balloon) {
        Intrinsics.checkNotNullParameter(view, "<this>");
        Intrinsics.checkNotNullParameter(balloon, "balloon");
        showAlignStart$default(view, balloon, 0, 0, 6, null);
    }

    public static /* synthetic */ void showAlignStart$default(View view, Balloon balloon, int i, int i2, int i3, Object obj) {
        if ((i3 & 2) != 0) {
            i = 0;
        }
        if ((i3 & 4) != 0) {
            i2 = 0;
        }
        showAlignStart(view, balloon, i, i2);
    }

    public static final /* synthetic */ void showAlignTop(View view, Balloon balloon) {
        Intrinsics.checkNotNullParameter(view, "<this>");
        Intrinsics.checkNotNullParameter(balloon, "balloon");
        showAlignTop$default(view, balloon, 0, 0, 6, null);
    }

    public static /* synthetic */ void showAlignTop$default(View view, Balloon balloon, int i, int i2, int i3, Object obj) {
        if ((i3 & 2) != 0) {
            i = 0;
        }
        if ((i3 & 4) != 0) {
            i2 = 0;
        }
        showAlignTop(view, balloon, i, i2);
    }

    public static final /* synthetic */ void showAsDropDown(View view, Balloon balloon) {
        Intrinsics.checkNotNullParameter(view, "<this>");
        Intrinsics.checkNotNullParameter(balloon, "balloon");
        showAsDropDown$default(view, balloon, 0, 0, 6, null);
    }

    public static /* synthetic */ void showAsDropDown$default(View view, Balloon balloon, int i, int i2, int i3, Object obj) {
        if ((i3 & 2) != 0) {
            i = 0;
        }
        if ((i3 & 4) != 0) {
            i2 = 0;
        }
        showAsDropDown(view, balloon, i, i2);
    }

    public static final /* synthetic */ void showAtCenter(View view, Balloon balloon) {
        Intrinsics.checkNotNullParameter(view, "<this>");
        Intrinsics.checkNotNullParameter(balloon, "balloon");
        showAtCenter$default(view, balloon, 0, 0, null, 14, null);
    }

    public static /* synthetic */ void showAtCenter$default(View view, Balloon balloon, int i, int i2, BalloonCenterAlign balloonCenterAlign, int i3, Object obj) {
        if ((i3 & 2) != 0) {
            i = 0;
        }
        if ((i3 & 4) != 0) {
            i2 = 0;
        }
        if ((i3 & 8) != 0) {
            balloonCenterAlign = BalloonCenterAlign.TOP;
        }
        showAtCenter(view, balloon, i, i2, balloonCenterAlign);
    }

    public static final /* synthetic */ void showAlign(View view, Balloon balloon, BalloonAlign align, List subAnchorList) {
        Intrinsics.checkNotNullParameter(view, "<this>");
        Intrinsics.checkNotNullParameter(balloon, "balloon");
        Intrinsics.checkNotNullParameter(align, "align");
        Intrinsics.checkNotNullParameter(subAnchorList, "subAnchorList");
        showAlign$default(view, balloon, align, subAnchorList, 0, 0, 24, null);
    }

    public static final /* synthetic */ void showAlignBottom(View view, Balloon balloon, int i) {
        Intrinsics.checkNotNullParameter(view, "<this>");
        Intrinsics.checkNotNullParameter(balloon, "balloon");
        showAlignBottom$default(view, balloon, i, 0, 4, null);
    }

    public static final /* synthetic */ void showAlignEnd(View view, Balloon balloon, int i) {
        Intrinsics.checkNotNullParameter(view, "<this>");
        Intrinsics.checkNotNullParameter(balloon, "balloon");
        showAlignEnd$default(view, balloon, i, 0, 4, null);
    }

    @InterfaceC4935d
    public static final /* synthetic */ void showAlignLeft(View view, Balloon balloon, int i) {
        Intrinsics.checkNotNullParameter(view, "<this>");
        Intrinsics.checkNotNullParameter(balloon, "balloon");
        showAlignLeft$default(view, balloon, i, 0, 4, null);
    }

    @InterfaceC4935d
    public static final /* synthetic */ void showAlignRight(View view, Balloon balloon, int i) {
        Intrinsics.checkNotNullParameter(view, "<this>");
        Intrinsics.checkNotNullParameter(balloon, "balloon");
        showAlignRight$default(view, balloon, i, 0, 4, null);
    }

    public static final /* synthetic */ void showAlignStart(View view, Balloon balloon, int i) {
        Intrinsics.checkNotNullParameter(view, "<this>");
        Intrinsics.checkNotNullParameter(balloon, "balloon");
        showAlignStart$default(view, balloon, i, 0, 4, null);
    }

    public static final /* synthetic */ void showAlignTop(View view, Balloon balloon, int i) {
        Intrinsics.checkNotNullParameter(view, "<this>");
        Intrinsics.checkNotNullParameter(balloon, "balloon");
        showAlignTop$default(view, balloon, i, 0, 4, null);
    }

    public static final /* synthetic */ void showAsDropDown(View view, Balloon balloon, int i) {
        Intrinsics.checkNotNullParameter(view, "<this>");
        Intrinsics.checkNotNullParameter(balloon, "balloon");
        showAsDropDown$default(view, balloon, i, 0, 4, null);
    }

    public static final /* synthetic */ void showAtCenter(View view, Balloon balloon, int i) {
        Intrinsics.checkNotNullParameter(view, "<this>");
        Intrinsics.checkNotNullParameter(balloon, "balloon");
        showAtCenter$default(view, balloon, i, 0, null, 12, null);
    }

    public static final /* synthetic */ void showAlign(View view, Balloon balloon, BalloonAlign align, List subAnchorList, int i) {
        Intrinsics.checkNotNullParameter(view, "<this>");
        Intrinsics.checkNotNullParameter(balloon, "balloon");
        Intrinsics.checkNotNullParameter(align, "align");
        Intrinsics.checkNotNullParameter(subAnchorList, "subAnchorList");
        showAlign$default(view, balloon, align, subAnchorList, i, 0, 16, null);
    }

    public static final /* synthetic */ void showAlignBottom(final View view, final Balloon balloon, final int i, final int i2) {
        Intrinsics.checkNotNullParameter(view, "<this>");
        Intrinsics.checkNotNullParameter(balloon, "balloon");
        view.post(new Runnable() { // from class: com.skydoves.balloon.BalloonExtensionKt$showAlignBottom$$inlined$balloon$1
            @Override // java.lang.Runnable
            public final void run() {
                balloon.showAlignBottom(view, i, i2);
            }
        });
    }

    public static final /* synthetic */ void showAlignEnd(final View view, final Balloon balloon, final int i, final int i2) {
        Intrinsics.checkNotNullParameter(view, "<this>");
        Intrinsics.checkNotNullParameter(balloon, "balloon");
        view.post(new Runnable() { // from class: com.skydoves.balloon.BalloonExtensionKt$showAlignEnd$$inlined$balloon$1
            @Override // java.lang.Runnable
            public final void run() {
                balloon.showAlignEnd(view, i, i2);
            }
        });
    }

    @InterfaceC4935d
    public static final /* synthetic */ void showAlignLeft(final View view, final Balloon balloon, final int i, final int i2) {
        Intrinsics.checkNotNullParameter(view, "<this>");
        Intrinsics.checkNotNullParameter(balloon, "balloon");
        view.post(new Runnable() { // from class: com.skydoves.balloon.BalloonExtensionKt$showAlignLeft$$inlined$balloon$1
            @Override // java.lang.Runnable
            public final void run() {
                balloon.showAlignLeft(view, i, i2);
            }
        });
    }

    @InterfaceC4935d
    public static final /* synthetic */ void showAlignRight(final View view, final Balloon balloon, final int i, final int i2) {
        Intrinsics.checkNotNullParameter(view, "<this>");
        Intrinsics.checkNotNullParameter(balloon, "balloon");
        view.post(new Runnable() { // from class: com.skydoves.balloon.BalloonExtensionKt$showAlignRight$$inlined$balloon$1
            @Override // java.lang.Runnable
            public final void run() {
                balloon.showAlignRight(view, i, i2);
            }
        });
    }

    public static final /* synthetic */ void showAlignStart(final View view, final Balloon balloon, final int i, final int i2) {
        Intrinsics.checkNotNullParameter(view, "<this>");
        Intrinsics.checkNotNullParameter(balloon, "balloon");
        view.post(new Runnable() { // from class: com.skydoves.balloon.BalloonExtensionKt$showAlignStart$$inlined$balloon$1
            @Override // java.lang.Runnable
            public final void run() {
                balloon.showAlignStart(view, i, i2);
            }
        });
    }

    public static final /* synthetic */ void showAlignTop(final View view, final Balloon balloon, final int i, final int i2) {
        Intrinsics.checkNotNullParameter(view, "<this>");
        Intrinsics.checkNotNullParameter(balloon, "balloon");
        view.post(new Runnable() { // from class: com.skydoves.balloon.BalloonExtensionKt$showAlignTop$$inlined$balloon$1
            @Override // java.lang.Runnable
            public final void run() {
                balloon.showAlignTop(view, i, i2);
            }
        });
    }

    public static final /* synthetic */ void showAsDropDown(final View view, final Balloon balloon, final int i, final int i2) {
        Intrinsics.checkNotNullParameter(view, "<this>");
        Intrinsics.checkNotNullParameter(balloon, "balloon");
        view.post(new Runnable() { // from class: com.skydoves.balloon.BalloonExtensionKt$showAsDropDown$$inlined$balloon$1
            @Override // java.lang.Runnable
            public final void run() {
                balloon.showAsDropDown(view, i, i2);
            }
        });
    }

    public static final /* synthetic */ void showAtCenter(View view, Balloon balloon, int i, int i2) {
        Intrinsics.checkNotNullParameter(view, "<this>");
        Intrinsics.checkNotNullParameter(balloon, "balloon");
        showAtCenter$default(view, balloon, i, i2, null, 8, null);
    }

    public static final /* synthetic */ void showAlign(final View view, final Balloon balloon, final BalloonAlign align, final List subAnchorList, final int i, final int i2) {
        Intrinsics.checkNotNullParameter(view, "<this>");
        Intrinsics.checkNotNullParameter(balloon, "balloon");
        Intrinsics.checkNotNullParameter(align, "align");
        Intrinsics.checkNotNullParameter(subAnchorList, "subAnchorList");
        view.post(new Runnable() { // from class: com.skydoves.balloon.BalloonExtensionKt$showAlign$$inlined$balloon$1
            @Override // java.lang.Runnable
            public final void run() {
                balloon.showAlign(align, view, subAnchorList, i, i2);
            }
        });
    }

    public static final /* synthetic */ void showAtCenter(final View view, final Balloon balloon, final int i, final int i2, final BalloonCenterAlign centerAlign) {
        Intrinsics.checkNotNullParameter(view, "<this>");
        Intrinsics.checkNotNullParameter(balloon, "balloon");
        Intrinsics.checkNotNullParameter(centerAlign, "centerAlign");
        view.post(new Runnable() { // from class: com.skydoves.balloon.BalloonExtensionKt$showAtCenter$$inlined$balloon$1
            @Override // java.lang.Runnable
            public final void run() {
                balloon.showAtCenter(view, i, i2, centerAlign);
            }
        });
    }
}

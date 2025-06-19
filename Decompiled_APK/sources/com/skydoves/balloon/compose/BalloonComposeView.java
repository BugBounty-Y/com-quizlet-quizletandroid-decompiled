package com.skydoves.balloon.compose;

import android.annotation.SuppressLint;
import android.content.Context;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import androidx.compose.runtime.AbstractC0827t;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.platform.AbstractC0930a;
import androidx.lifecycle.J;
import androidx.lifecycle.p0;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3347h2;
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
import java.util.UUID;
import kotlin.InterfaceC4935d;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
@SuppressLint({"ViewConstructor"})
/* loaded from: classes3.dex */
public final class BalloonComposeView extends AbstractC0930a implements BalloonWindow {
    public static final int $stable = 0;

    @NotNull
    private final View anchorView;

    @NotNull
    private final Balloon balloon;

    @NotNull
    private InterfaceC0773a0 balloonLayoutInfo;

    @NotNull
    private final InterfaceC0773a0 content$delegate;
    private final J lifecycleOwner;
    private boolean shouldCreateCompositionOnAttachedToWindow;

    /* JADX WARN: Illegal instructions before constructor call */
    public BalloonComposeView(@NotNull View anchorView, boolean z, @NotNull Balloon.Builder builder, @NotNull UUID balloonID) {
        Intrinsics.checkNotNullParameter(anchorView, "anchorView");
        Intrinsics.checkNotNullParameter(builder, "builder");
        Intrinsics.checkNotNullParameter(balloonID, "balloonID");
        Context context = anchorView.getContext();
        Intrinsics.checkNotNullExpressionValue(context, "getContext(...)");
        super(context, null);
        this.anchorView = anchorView;
        J jF = p0.f(getAnchorView());
        this.lifecycleOwner = jF;
        Balloon.Builder isComposableContent = builder.setLifecycleOwner(jF).setIsComposableContent(z);
        if (z) {
            isComposableContent.setLayout((View) this);
        }
        this.balloon = isComposableContent.build();
        this.content$delegate = C0776c.z(ComposableSingletons$BalloonComposeViewKt.INSTANCE.m149getLambda1$balloon_compose_release());
        this.balloonLayoutInfo = C0776c.z(null);
        p0.n(this, jF);
        p0.o(this, p0.g(getAnchorView()));
        AbstractC3347h2.e(this, AbstractC3347h2.b(getAnchorView()));
        setTag(com.quizlet.quizletandroid.R.id.compose_view_saveable_id_tag, "BalloonComposeView:" + balloonID);
    }

    private final kotlin.jvm.functions.c getContent() {
        return (kotlin.jvm.functions.c) this.content$delegate.getValue();
    }

    private final void setContent(kotlin.jvm.functions.c cVar) {
        this.content$delegate.setValue(cVar);
    }

    @Override // androidx.compose.ui.platform.AbstractC0930a
    public void Content(InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.X(-441221009);
        getContent().invoke(this, c0814p, Integer.valueOf(i & 14));
        c0814p.p(false);
    }

    @Override // com.skydoves.balloon.compose.BalloonWindow
    public Object awaitAlign(@NotNull BalloonAlign balloonAlign, @NotNull View view, @NotNull List<? extends View> list, int i, int i2, @NotNull h<? super Unit> hVar) {
        Object objAwaitAlign = getBalloon().awaitAlign(balloonAlign, view, list, i, i2, hVar);
        return objAwaitAlign == kotlin.coroutines.intrinsics.a.a ? objAwaitAlign : Unit.a;
    }

    @Override // com.skydoves.balloon.compose.BalloonWindow
    public Object awaitAlignBottom(int i, int i2, @NotNull h<? super Unit> hVar) {
        Object objAwaitAlignBottom = getBalloon().awaitAlignBottom(getAnchorView(), i, i2, hVar);
        return objAwaitAlignBottom == kotlin.coroutines.intrinsics.a.a ? objAwaitAlignBottom : Unit.a;
    }

    @Override // com.skydoves.balloon.compose.BalloonWindow
    public Object awaitAlignEnd(int i, int i2, @NotNull h<? super Unit> hVar) {
        Object objAwaitAlignEnd = getBalloon().awaitAlignEnd(getAnchorView(), i, i2, hVar);
        return objAwaitAlignEnd == kotlin.coroutines.intrinsics.a.a ? objAwaitAlignEnd : Unit.a;
    }

    @Override // com.skydoves.balloon.compose.BalloonWindow
    public Object awaitAlignStart(int i, int i2, @NotNull h<? super Unit> hVar) {
        Object objAwaitAlignStart = getBalloon().awaitAlignStart(getAnchorView(), i, i2, hVar);
        return objAwaitAlignStart == kotlin.coroutines.intrinsics.a.a ? objAwaitAlignStart : Unit.a;
    }

    @Override // com.skydoves.balloon.compose.BalloonWindow
    public Object awaitAlignTop(int i, int i2, @NotNull h<? super Unit> hVar) {
        Object objAwaitAlignTop = getBalloon().awaitAlignTop(getAnchorView(), i, i2, hVar);
        return objAwaitAlignTop == kotlin.coroutines.intrinsics.a.a ? objAwaitAlignTop : Unit.a;
    }

    @Override // com.skydoves.balloon.compose.BalloonWindow
    public Object awaitAsDropDown(int i, int i2, @NotNull h<? super Unit> hVar) {
        Object objAwaitAsDropDown = getBalloon().awaitAsDropDown(getAnchorView(), i, i2, hVar);
        return objAwaitAsDropDown == kotlin.coroutines.intrinsics.a.a ? objAwaitAsDropDown : Unit.a;
    }

    @Override // com.skydoves.balloon.compose.BalloonWindow
    public Object awaitAtCenter(int i, int i2, @NotNull BalloonCenterAlign balloonCenterAlign, @NotNull h<? super Unit> hVar) {
        Object objAwaitAtCenter = getBalloon().awaitAtCenter(getAnchorView(), i, i2, balloonCenterAlign, hVar);
        return objAwaitAtCenter == kotlin.coroutines.intrinsics.a.a ? objAwaitAtCenter : Unit.a;
    }

    @Override // com.skydoves.balloon.compose.BalloonWindow
    public void clearAllPreferences() {
        getBalloon().clearAllPreferences();
    }

    @Override // com.skydoves.balloon.compose.BalloonWindow
    public void dismiss() {
        getBalloon().dismiss();
    }

    @Override // com.skydoves.balloon.compose.BalloonWindow
    public boolean dismissWithDelay(long j) {
        return getBalloon().dismissWithDelay(j);
    }

    public final void dispose$balloon_compose_release() {
        getBalloon().dismiss();
        p0.n(this, null);
        p0.o(this, null);
        AbstractC3347h2.e(this, null);
    }

    @Override // android.view.ViewGroup, android.view.View
    @NotNull
    public CharSequence getAccessibilityClassName() {
        String name = BalloonComposeView.class.getName();
        Intrinsics.checkNotNullExpressionValue(name, "getName(...)");
        return name;
    }

    @Override // com.skydoves.balloon.compose.BalloonWindow
    @NotNull
    public View getAnchorView() {
        return this.anchorView;
    }

    @Override // com.skydoves.balloon.compose.BalloonWindow
    @NotNull
    public Balloon getBalloon() {
        return this.balloon;
    }

    @Override // com.skydoves.balloon.compose.BalloonWindow
    @NotNull
    public View getBalloonArrowView() {
        return getBalloon().getBalloonArrowView();
    }

    @NotNull
    public final InterfaceC0773a0 getBalloonLayoutInfo$balloon_compose_release() {
        return this.balloonLayoutInfo;
    }

    @Override // com.skydoves.balloon.compose.BalloonWindow
    @NotNull
    public ViewGroup getContentView() {
        return getBalloon().getContentView();
    }

    @Override // androidx.compose.ui.platform.AbstractC0930a
    public boolean getShouldCreateCompositionOnAttachedToWindow() {
        return this.shouldCreateCompositionOnAttachedToWindow;
    }

    @Override // com.skydoves.balloon.compose.BalloonWindow
    @NotNull
    public Balloon relayShowAlign(@NotNull BalloonAlign align, @NotNull Balloon balloon, int i, int i2) {
        Intrinsics.checkNotNullParameter(align, "align");
        Intrinsics.checkNotNullParameter(balloon, "balloon");
        return balloon.relayShowAlign(align, balloon, getAnchorView(), i, i2);
    }

    @Override // com.skydoves.balloon.compose.BalloonWindow
    @NotNull
    public Balloon relayShowAlignBottom(@NotNull Balloon balloon, int i, int i2) {
        Intrinsics.checkNotNullParameter(balloon, "balloon");
        return balloon.relayShowAlignBottom(balloon, getAnchorView(), i, i2);
    }

    @Override // com.skydoves.balloon.compose.BalloonWindow
    @NotNull
    public Balloon relayShowAlignEnd(@NotNull Balloon balloon, int i, int i2) {
        Intrinsics.checkNotNullParameter(balloon, "balloon");
        return balloon.relayShowAlignEnd(balloon, getAnchorView(), i, i2);
    }

    @Override // com.skydoves.balloon.compose.BalloonWindow
    @InterfaceC4935d
    @NotNull
    public Balloon relayShowAlignLeft(@NotNull Balloon balloon, int i, int i2) {
        Intrinsics.checkNotNullParameter(balloon, "balloon");
        return balloon.relayShowAlignLeft(balloon, getAnchorView(), i, i2);
    }

    @Override // com.skydoves.balloon.compose.BalloonWindow
    @InterfaceC4935d
    @NotNull
    public Balloon relayShowAlignRight(@NotNull Balloon balloon, int i, int i2) {
        Intrinsics.checkNotNullParameter(balloon, "balloon");
        return balloon.relayShowAlignRight(balloon, getAnchorView(), i, i2);
    }

    @Override // com.skydoves.balloon.compose.BalloonWindow
    @NotNull
    public Balloon relayShowAlignStart(@NotNull Balloon balloon, int i, int i2) {
        Intrinsics.checkNotNullParameter(balloon, "balloon");
        return balloon.relayShowAlignStart(balloon, getAnchorView(), i, i2);
    }

    @Override // com.skydoves.balloon.compose.BalloonWindow
    @NotNull
    public Balloon relayShowAlignTop(@NotNull Balloon balloon, int i, int i2) {
        Intrinsics.checkNotNullParameter(balloon, "balloon");
        return balloon.relayShowAlignTop(balloon, getAnchorView(), i, i2);
    }

    @Override // com.skydoves.balloon.compose.BalloonWindow
    @NotNull
    public Balloon relayShowAsDropDown(@NotNull Balloon balloon, int i, int i2) {
        Intrinsics.checkNotNullParameter(balloon, "balloon");
        return balloon.relayShowAsDropDown(balloon, getAnchorView(), i, i2);
    }

    @Override // com.skydoves.balloon.compose.BalloonWindow
    @NotNull
    public Balloon relayShowAtCenter(@NotNull Balloon balloon, int i, int i2, @NotNull BalloonCenterAlign centerAlign) {
        Intrinsics.checkNotNullParameter(balloon, "balloon");
        Intrinsics.checkNotNullParameter(centerAlign, "centerAlign");
        return balloon.relayShowAtCenter(balloon, getAnchorView(), i, i2, centerAlign);
    }

    public final void setBalloonLayoutInfo$balloon_compose_release(@NotNull InterfaceC0773a0 interfaceC0773a0) {
        Intrinsics.checkNotNullParameter(interfaceC0773a0, "<set-?>");
        this.balloonLayoutInfo = interfaceC0773a0;
    }

    @Override // com.skydoves.balloon.compose.BalloonWindow
    @NotNull
    public Balloon setIsAttachedInDecor(boolean z) {
        return getBalloon().setIsAttachedInDecor(z);
    }

    @Override // com.skydoves.balloon.compose.BalloonWindow
    public void setOnBalloonClickListener(OnBalloonClickListener onBalloonClickListener) {
        getBalloon().setOnBalloonClickListener(onBalloonClickListener);
    }

    @Override // com.skydoves.balloon.compose.BalloonWindow
    public void setOnBalloonDismissListener(OnBalloonDismissListener onBalloonDismissListener) {
        getBalloon().setOnBalloonDismissListener(onBalloonDismissListener);
    }

    @Override // com.skydoves.balloon.compose.BalloonWindow
    public void setOnBalloonInitializedListener(OnBalloonInitializedListener onBalloonInitializedListener) {
        getBalloon().setOnBalloonInitializedListener(onBalloonInitializedListener);
    }

    @Override // com.skydoves.balloon.compose.BalloonWindow
    public void setOnBalloonOutsideTouchListener(OnBalloonOutsideTouchListener onBalloonOutsideTouchListener) {
        getBalloon().setOnBalloonOutsideTouchListener(onBalloonOutsideTouchListener);
    }

    @Override // com.skydoves.balloon.compose.BalloonWindow
    public void setOnBalloonOverlayClickListener(OnBalloonOverlayClickListener onBalloonOverlayClickListener) {
        getBalloon().setOnBalloonOverlayClickListener(onBalloonOverlayClickListener);
    }

    @Override // com.skydoves.balloon.compose.BalloonWindow
    public void setOnBalloonOverlayTouchListener(View.OnTouchListener onTouchListener) {
        getBalloon().setOnBalloonOverlayTouchListener(onTouchListener);
    }

    @Override // com.skydoves.balloon.compose.BalloonWindow
    public void setOnBalloonTouchListener(View.OnTouchListener onTouchListener) {
        getBalloon().setOnBalloonTouchListener(onTouchListener);
    }

    @Override // com.skydoves.balloon.compose.BalloonWindow
    public boolean shouldShowUp() {
        return getBalloon().shouldShowUp();
    }

    @Override // com.skydoves.balloon.compose.BalloonWindow
    public void showAlign(@NotNull BalloonAlign align, @NotNull View mainAnchor, @NotNull List<? extends View> subAnchorList, int i, int i2) {
        Intrinsics.checkNotNullParameter(align, "align");
        Intrinsics.checkNotNullParameter(mainAnchor, "mainAnchor");
        Intrinsics.checkNotNullParameter(subAnchorList, "subAnchorList");
        getBalloon().showAlign(align, mainAnchor, subAnchorList, i, i2);
    }

    @Override // com.skydoves.balloon.compose.BalloonWindow
    public void showAlignBottom(int i, int i2) {
        getBalloon().showAlignBottom(getAnchorView(), i, i2);
    }

    @Override // com.skydoves.balloon.compose.BalloonWindow
    public void showAlignEnd(int i, int i2) {
        getBalloon().showAlignEnd(getAnchorView(), i, i2);
    }

    @Override // com.skydoves.balloon.compose.BalloonWindow
    @InterfaceC4935d
    public void showAlignLeft(int i, int i2) {
        getBalloon().showAlignLeft(getAnchorView(), i, i2);
    }

    @Override // com.skydoves.balloon.compose.BalloonWindow
    @InterfaceC4935d
    public void showAlignRight(int i, int i2) {
        getBalloon().showAlignRight(getAnchorView(), i, i2);
    }

    @Override // com.skydoves.balloon.compose.BalloonWindow
    public void showAlignStart(int i, int i2) {
        getBalloon().showAlignStart(getAnchorView(), i, i2);
    }

    @Override // com.skydoves.balloon.compose.BalloonWindow
    public void showAlignTop(int i, int i2) {
        getBalloon().showAlignTop(getAnchorView(), i, i2);
    }

    @Override // com.skydoves.balloon.compose.BalloonWindow
    public void showAsDropDown(int i, int i2) {
        getBalloon().showAsDropDown(getAnchorView(), i, i2);
    }

    @Override // com.skydoves.balloon.compose.BalloonWindow
    public void showAtCenter(int i, int i2, @NotNull BalloonCenterAlign centerAlign) {
        Intrinsics.checkNotNullParameter(centerAlign, "centerAlign");
        getBalloon().showAtCenter(getAnchorView(), i, i2, centerAlign);
    }

    @Override // com.skydoves.balloon.compose.BalloonWindow
    public void update(int i, int i2) {
        Balloon.update$default(getBalloon(), getAnchorView(), i, i2, 0, 0, 24, null);
    }

    @Override // com.skydoves.balloon.compose.BalloonWindow
    public void updateAlign(@NotNull BalloonAlign align, int i, int i2) {
        Intrinsics.checkNotNullParameter(align, "align");
        Balloon.updateAlign$default(getBalloon(), align, getAnchorView(), i, i2, 0, 0, 48, null);
    }

    @Override // com.skydoves.balloon.compose.BalloonWindow
    public void updateAlignBottom(int i, int i2) {
        Balloon.updateAlignBottom$default(getBalloon(), getAnchorView(), i, i2, 0, 0, 24, null);
    }

    @Override // com.skydoves.balloon.compose.BalloonWindow
    public void updateAlignEnd(int i, int i2) {
        Balloon.updateAlignEnd$default(getBalloon(), getAnchorView(), i, i2, 0, 0, 24, null);
    }

    @Override // com.skydoves.balloon.compose.BalloonWindow
    public void updateAlignStart(int i, int i2) {
        Balloon.updateAlignStart$default(getBalloon(), getAnchorView(), i, i2, 0, 0, 24, null);
    }

    @Override // com.skydoves.balloon.compose.BalloonWindow
    public void updateAlignTop(int i, int i2) {
        Balloon.updateAlignTop$default(getBalloon(), getAnchorView(), i, i2, 0, 0, 24, null);
    }

    @Override // com.skydoves.balloon.compose.BalloonWindow
    @InternalBalloonApi
    public void updateSizeOfBalloonCard(int i, int i2) {
        getBalloon().updateSizeOfBalloonCard(i, i2);
    }

    /* renamed from: updateSizeOfBalloonCard-ozmzZPI$balloon_compose_release, reason: not valid java name */
    public final void m148updateSizeOfBalloonCardozmzZPI$balloon_compose_release(long j) {
        int i = (int) (j >> 32);
        int i2 = (int) (j & 4294967295L);
        getBalloon().updateSizeOfBalloonCard(i, i2);
        ViewGroup.LayoutParams layoutParams = getLayoutParams();
        if (layoutParams == null) {
            throw new NullPointerException("null cannot be cast to non-null type android.view.ViewGroup.LayoutParams");
        }
        layoutParams.width = i;
        layoutParams.height = i2;
        setLayoutParams(layoutParams);
    }

    @Override // com.skydoves.balloon.compose.BalloonWindow
    public void setOnBalloonClickListener(@NotNull Function1<? super View, Unit> block) {
        Intrinsics.checkNotNullParameter(block, "block");
        getBalloon().setOnBalloonClickListener(block);
    }

    @Override // com.skydoves.balloon.compose.BalloonWindow
    public void setOnBalloonDismissListener(@NotNull Function0<Unit> block) {
        Intrinsics.checkNotNullParameter(block, "block");
        getBalloon().setOnBalloonDismissListener(block);
    }

    @Override // com.skydoves.balloon.compose.BalloonWindow
    public void setOnBalloonInitializedListener(@NotNull Function1<? super View, Unit> block) {
        Intrinsics.checkNotNullParameter(block, "block");
        getBalloon().setOnBalloonInitializedListener(block);
    }

    @Override // com.skydoves.balloon.compose.BalloonWindow
    public void setOnBalloonOutsideTouchListener(@NotNull Function2<? super View, ? super MotionEvent, Unit> block) {
        Intrinsics.checkNotNullParameter(block, "block");
        getBalloon().setOnBalloonOutsideTouchListener(block);
    }

    @Override // com.skydoves.balloon.compose.BalloonWindow
    public void setOnBalloonOverlayClickListener(@NotNull Function0<Unit> block) {
        Intrinsics.checkNotNullParameter(block, "block");
        getBalloon().setOnBalloonOverlayClickListener(block);
    }

    @Override // com.skydoves.balloon.compose.BalloonWindow
    public void setOnBalloonOverlayTouchListener(@NotNull Function2<? super View, ? super MotionEvent, Boolean> block) {
        Intrinsics.checkNotNullParameter(block, "block");
        getBalloon().setOnBalloonOverlayTouchListener(block);
    }

    public final void setContent(@NotNull AbstractC0827t compositionContext, @NotNull kotlin.jvm.functions.c content) {
        Intrinsics.checkNotNullParameter(compositionContext, "compositionContext");
        Intrinsics.checkNotNullParameter(content, "content");
        setParentCompositionContext(compositionContext);
        this.shouldCreateCompositionOnAttachedToWindow = true;
        setContent(content);
        if (isAttachedToWindow()) {
            createComposition();
        }
    }
}

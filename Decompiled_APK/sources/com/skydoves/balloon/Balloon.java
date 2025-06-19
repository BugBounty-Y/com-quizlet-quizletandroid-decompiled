package com.skydoves.balloon;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.annotation.SuppressLint;
import android.app.Activity;
import android.content.Context;
import android.content.res.ColorStateList;
import android.content.res.Resources;
import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.LinearGradient;
import android.graphics.Paint;
import android.graphics.Point;
import android.graphics.PorterDuff;
import android.graphics.PorterDuffXfermode;
import android.graphics.Rect;
import android.graphics.Shader;
import android.graphics.Typeface;
import android.graphics.drawable.BitmapDrawable;
import android.graphics.drawable.ColorDrawable;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.GradientDrawable;
import android.os.Handler;
import android.os.Looper;
import android.text.method.MovementMethod;
import android.util.TypedValue;
import android.view.LayoutInflater;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewAnimationUtils;
import android.view.ViewGroup;
import android.view.ViewOutlineProvider;
import android.view.animation.Animation;
import android.view.animation.AnimationUtils;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.PopupWindow;
import android.widget.TextView;
import androidx.core.view.L;
import androidx.core.view.V;
import androidx.lifecycle.I;
import androidx.lifecycle.InterfaceC1250k;
import androidx.lifecycle.J;
import com.amazon.aps.ads.util.adview.d;
import com.google.android.gms.internal.mlkit_vision_camera.D1;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.quizletandroid.ui.studymodes.testmode.start.p;
import com.skydoves.balloon.Balloon;
import com.skydoves.balloon.IconForm;
import com.skydoves.balloon.TextForm;
import com.skydoves.balloon.animations.BalloonRotateAnimation;
import com.skydoves.balloon.annotations.Dp;
import com.skydoves.balloon.annotations.InternalBalloonApi;
import com.skydoves.balloon.annotations.Sp;
import com.skydoves.balloon.databinding.BalloonLayoutBodyBinding;
import com.skydoves.balloon.databinding.BalloonLayoutOverlayBinding;
import com.skydoves.balloon.extensions.ContextExtensionKt;
import com.skydoves.balloon.extensions.DrawableExtensionKt;
import com.skydoves.balloon.extensions.GlobalExtensionKt;
import com.skydoves.balloon.extensions.TextViewExtensionKt;
import com.skydoves.balloon.extensions.ViewExtensionKt;
import com.skydoves.balloon.internals.DefinitionKt;
import com.skydoves.balloon.overlay.BalloonAnchorOverlayView;
import com.skydoves.balloon.overlay.BalloonOverlayAnimation;
import com.skydoves.balloon.overlay.BalloonOverlayOval;
import com.skydoves.balloon.overlay.BalloonOverlayShape;
import com.skydoves.balloon.radius.RadiusLayout;
import com.skydoves.balloon.vectortext.VectorTextView;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.WeakHashMap;
import kotlin.InterfaceC4935d;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Pair;
import kotlin.Unit;
import kotlin.collections.A;
import kotlin.collections.CollectionsKt;
import kotlin.collections.K;
import kotlin.collections.P;
import kotlin.coroutines.h;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.k;
import kotlin.l;
import kotlin.ranges.IntRange;
import kotlinx.coroutines.C;
import kotlinx.coroutines.E;
import kotlinx.coroutines.O;
import kotlinx.coroutines.internal.m;
import kotlinx.coroutines.scheduling.e;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class Balloon implements InterfaceC1250k {
    private static boolean isConsumerActive;

    @NotNull
    private final k autoDismissRunnable$delegate;

    @NotNull
    private final k balloonPersistence$delegate;

    @NotNull
    private final BalloonLayoutBodyBinding binding;

    @NotNull
    private final PopupWindow bodyWindow;

    @NotNull
    private final Builder builder;

    @NotNull
    private final Context context;
    private BalloonAlign currentAlign;
    private boolean destroyed;

    @NotNull
    private final k handler$delegate;
    private boolean isShowing;
    public OnBalloonInitializedListener onBalloonInitializedListener;

    @NotNull
    private final BalloonLayoutOverlayBinding overlayBinding;

    @NotNull
    private final PopupWindow overlayWindow;
    private Pair<MotionEvent, Boolean> passedEventActionDownEvent;

    @NotNull
    public static final Companion Companion = new Companion(null);

    @NotNull
    private static final k channel$delegate = l.b(new com.quizlet.quizletandroid.ui.startpage.nav2.composables.b(26));

    @NotNull
    private static final k scope$delegate = l.b(new com.quizlet.quizletandroid.ui.startpage.nav2.composables.b(27));

    @BalloonInlineDsl
    @Metadata
    public static final class Builder {
        private float alpha;
        private int arrowAlignAnchorPadding;
        private float arrowAlignAnchorPaddingRatio;
        private int arrowBottomPadding;
        private int arrowColor;
        private boolean arrowColorMatchBalloon;
        private Drawable arrowDrawable;
        private float arrowElevation;
        private int arrowLeftPadding;

        @NotNull
        private ArrowOrientation arrowOrientation;

        @NotNull
        private ArrowOrientationRules arrowOrientationRules;
        private float arrowPosition;

        @NotNull
        private ArrowPositionRules arrowPositionRules;
        private int arrowRightPadding;
        private int arrowSize;
        private int arrowTopPadding;
        private long autoDismissDuration;
        private int backgroundColor;
        private Drawable backgroundDrawable;

        @NotNull
        private BalloonAnimation balloonAnimation;
        private int balloonAnimationStyle;

        @NotNull
        private BalloonHighlightAnimation balloonHighlightAnimation;
        private long balloonHighlightAnimationStartDelay;
        private int balloonHighlightAnimationStyle;

        @NotNull
        private BalloonOverlayAnimation balloonOverlayAnimation;
        private int balloonOverlayAnimationStyle;
        private BalloonRotateAnimation balloonRotateAnimation;
        private long circularDuration;

        @NotNull
        private final Context context;
        private float cornerRadius;
        private boolean dismissWhenClicked;
        private boolean dismissWhenLifecycleOnPause;
        private boolean dismissWhenOverlayClicked;
        private boolean dismissWhenShowAgain;
        private boolean dismissWhenTouchMargin;
        private boolean dismissWhenTouchOutside;
        private float elevation;
        private boolean enableAutoSized;
        private int height;
        private int iconColor;

        @NotNull
        private CharSequence iconContentDescription;
        private Drawable iconDrawable;
        private IconForm iconForm;

        @NotNull
        private IconGravity iconGravity;
        private int iconHeight;
        private int iconSpace;
        private int iconWidth;
        private boolean includeFontPadding;
        private boolean isAttachedInDecor;
        private boolean isComposableContent;
        private boolean isFocusable;
        private boolean isRtlLayout;
        private boolean isStatusBarVisible;
        private boolean isVisibleArrow;
        private boolean isVisibleOverlay;
        private View layout;
        private Integer layoutRes;
        private I lifecycleObserver;
        private J lifecycleOwner;
        private int marginBottom;
        private int marginLeft;
        private int marginRight;
        private int marginTop;
        private float maxAutoSizeTextSize;
        private int maxWidth;
        private float maxWidthRatio;
        private int measuredWidth;
        private float minAutoSizeTextSize;
        private int minWidth;
        private float minWidthRatio;
        private MovementMethod movementMethod;
        private OnBalloonClickListener onBalloonClickListener;
        private OnBalloonDismissListener onBalloonDismissListener;
        private OnBalloonInitializedListener onBalloonInitializedListener;
        private OnBalloonOutsideTouchListener onBalloonOutsideTouchListener;
        private OnBalloonOverlayClickListener onBalloonOverlayClickListener;
        private View.OnTouchListener onBalloonOverlayTouchListener;
        private View.OnTouchListener onBalloonTouchListener;
        private int overlayColor;
        private int overlayGravity;
        private float overlayPadding;
        private int overlayPaddingColor;
        private Shader overlayPaddingShader;
        private Point overlayPosition;

        @NotNull
        private BalloonOverlayShape overlayShape;
        private int paddingBottom;
        private int paddingLeft;
        private int paddingRight;
        private int paddingTop;
        private boolean passTouchEventToAnchor;
        private String preferenceName;
        private Function0<Unit> runIfReachedShowCounts;
        private int showTimes;
        private int supportRtlLayoutFactor;

        @NotNull
        private CharSequence text;
        private int textColor;
        private TextForm textForm;
        private int textGravity;
        private boolean textIsHtml;
        private Float textLetterSpacing;
        private Float textLineSpacing;

        @Sp
        private float textSize;
        private int textTypeface;
        private Typeface textTypefaceObject;
        private int width;
        private float widthRatio;

        public Builder(@NotNull Context context) {
            Intrinsics.checkNotNullParameter(context, "context");
            this.context = context;
            this.width = Integer.MIN_VALUE;
            this.maxWidth = new Point(Resources.getSystem().getDisplayMetrics().widthPixels, Resources.getSystem().getDisplayMetrics().heightPixels).x;
            this.measuredWidth = Integer.MIN_VALUE;
            this.height = Integer.MIN_VALUE;
            this.isVisibleArrow = true;
            this.arrowColor = Integer.MIN_VALUE;
            this.arrowSize = AbstractC4178x.a(12, 1);
            this.arrowPosition = 0.5f;
            this.arrowPositionRules = ArrowPositionRules.ALIGN_BALLOON;
            this.arrowOrientationRules = ArrowOrientationRules.ALIGN_ANCHOR;
            this.arrowOrientation = ArrowOrientation.BOTTOM;
            this.arrowAlignAnchorPaddingRatio = 2.5f;
            this.backgroundColor = -16777216;
            this.cornerRadius = TypedValue.applyDimension(1, 5.0f, Resources.getSystem().getDisplayMetrics());
            this.text = "";
            this.textColor = -1;
            this.textSize = 12.0f;
            this.minAutoSizeTextSize = 12.0f;
            this.maxAutoSizeTextSize = 12.0f + 1;
            this.includeFontPadding = true;
            this.textGravity = 17;
            this.iconGravity = IconGravity.START;
            float f = 28;
            this.iconWidth = AbstractC4178x.a(f, 1);
            this.iconHeight = AbstractC4178x.a(f, 1);
            this.iconSpace = AbstractC4178x.a(8, 1);
            this.iconColor = Integer.MIN_VALUE;
            this.iconContentDescription = "";
            this.alpha = 1.0f;
            this.elevation = TypedValue.applyDimension(1, 2.0f, Resources.getSystem().getDisplayMetrics());
            this.overlayShape = BalloonOverlayOval.INSTANCE;
            this.overlayGravity = 17;
            this.dismissWhenTouchOutside = true;
            this.dismissWhenTouchMargin = true;
            this.dismissWhenOverlayClicked = true;
            this.autoDismissDuration = -1L;
            this.balloonAnimationStyle = Integer.MIN_VALUE;
            this.balloonOverlayAnimationStyle = Integer.MIN_VALUE;
            this.balloonAnimation = BalloonAnimation.FADE;
            this.balloonOverlayAnimation = BalloonOverlayAnimation.FADE;
            this.circularDuration = 500L;
            this.balloonHighlightAnimation = BalloonHighlightAnimation.NONE;
            this.balloonHighlightAnimationStyle = Integer.MIN_VALUE;
            this.showTimes = 1;
            boolean z = context.getResources().getConfiguration().getLayoutDirection() == 1;
            this.isRtlLayout = z;
            this.supportRtlLayoutFactor = DefinitionKt.unaryMinus(1, z);
            this.isFocusable = true;
            this.isStatusBarVisible = true;
            this.isAttachedInDecor = true;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static final Unit runIfReachedShowCounts$lambda$165$lambda$164(Runnable runnable) {
            runnable.run();
            return Unit.a;
        }

        public static /* synthetic */ Builder setBalloonHighlightAnimation$default(Builder builder, BalloonHighlightAnimation balloonHighlightAnimation, long j, int i, Object obj) {
            if ((i & 2) != 0) {
                j = 0;
            }
            return builder.setBalloonHighlightAnimation(balloonHighlightAnimation, j);
        }

        public static /* synthetic */ Builder setBalloonHighlightAnimationResource$default(Builder builder, int i, long j, int i2, Object obj) {
            if ((i2 & 2) != 0) {
                j = 0;
            }
            return builder.setBalloonHighlightAnimationResource(i, j);
        }

        @NotNull
        public final Balloon build() {
            return new Balloon(this.context, this, null);
        }

        public final float getAlpha() {
            return this.alpha;
        }

        public final int getArrowAlignAnchorPadding() {
            return this.arrowAlignAnchorPadding;
        }

        public final float getArrowAlignAnchorPaddingRatio() {
            return this.arrowAlignAnchorPaddingRatio;
        }

        public final int getArrowBottomPadding() {
            return this.arrowBottomPadding;
        }

        public final int getArrowColor() {
            return this.arrowColor;
        }

        public final boolean getArrowColorMatchBalloon() {
            return this.arrowColorMatchBalloon;
        }

        public final Drawable getArrowDrawable() {
            return this.arrowDrawable;
        }

        public final float getArrowElevation() {
            return this.arrowElevation;
        }

        public final /* synthetic */ float getArrowHalfSize() {
            return getArrowSize() * 0.5f;
        }

        public final int getArrowLeftPadding() {
            return this.arrowLeftPadding;
        }

        @NotNull
        public final ArrowOrientation getArrowOrientation() {
            return this.arrowOrientation;
        }

        @NotNull
        public final ArrowOrientationRules getArrowOrientationRules() {
            return this.arrowOrientationRules;
        }

        public final float getArrowPosition() {
            return this.arrowPosition;
        }

        @NotNull
        public final ArrowPositionRules getArrowPositionRules() {
            return this.arrowPositionRules;
        }

        public final int getArrowRightPadding() {
            return this.arrowRightPadding;
        }

        public final int getArrowSize() {
            return this.arrowSize;
        }

        public final int getArrowTopPadding() {
            return this.arrowTopPadding;
        }

        public final long getAutoDismissDuration() {
            return this.autoDismissDuration;
        }

        public final int getBackgroundColor() {
            return this.backgroundColor;
        }

        public final Drawable getBackgroundDrawable() {
            return this.backgroundDrawable;
        }

        @NotNull
        public final BalloonAnimation getBalloonAnimation() {
            return this.balloonAnimation;
        }

        public final int getBalloonAnimationStyle() {
            return this.balloonAnimationStyle;
        }

        @NotNull
        public final BalloonHighlightAnimation getBalloonHighlightAnimation() {
            return this.balloonHighlightAnimation;
        }

        public final long getBalloonHighlightAnimationStartDelay() {
            return this.balloonHighlightAnimationStartDelay;
        }

        public final int getBalloonHighlightAnimationStyle() {
            return this.balloonHighlightAnimationStyle;
        }

        @NotNull
        public final BalloonOverlayAnimation getBalloonOverlayAnimation() {
            return this.balloonOverlayAnimation;
        }

        public final int getBalloonOverlayAnimationStyle() {
            return this.balloonOverlayAnimationStyle;
        }

        public final BalloonRotateAnimation getBalloonRotateAnimation() {
            return this.balloonRotateAnimation;
        }

        public final long getCircularDuration() {
            return this.circularDuration;
        }

        public final float getCornerRadius() {
            return this.cornerRadius;
        }

        public final boolean getDismissWhenClicked() {
            return this.dismissWhenClicked;
        }

        public final boolean getDismissWhenLifecycleOnPause() {
            return this.dismissWhenLifecycleOnPause;
        }

        public final boolean getDismissWhenOverlayClicked() {
            return this.dismissWhenOverlayClicked;
        }

        public final boolean getDismissWhenShowAgain() {
            return this.dismissWhenShowAgain;
        }

        public final boolean getDismissWhenTouchMargin() {
            return this.dismissWhenTouchMargin;
        }

        public final boolean getDismissWhenTouchOutside() {
            return this.dismissWhenTouchOutside;
        }

        public final float getElevation() {
            return this.elevation;
        }

        public final boolean getEnableAutoSized() {
            return this.enableAutoSized;
        }

        public final int getHeight() {
            return this.height;
        }

        public final int getIconColor() {
            return this.iconColor;
        }

        @NotNull
        public final CharSequence getIconContentDescription() {
            return this.iconContentDescription;
        }

        public final Drawable getIconDrawable() {
            return this.iconDrawable;
        }

        public final IconForm getIconForm() {
            return this.iconForm;
        }

        @NotNull
        public final IconGravity getIconGravity() {
            return this.iconGravity;
        }

        public final int getIconHeight() {
            return this.iconHeight;
        }

        public final int getIconSpace() {
            return this.iconSpace;
        }

        public final int getIconWidth() {
            return this.iconWidth;
        }

        public final boolean getIncludeFontPadding() {
            return this.includeFontPadding;
        }

        public final View getLayout() {
            return this.layout;
        }

        public final Integer getLayoutRes() {
            return this.layoutRes;
        }

        public final I getLifecycleObserver() {
            return this.lifecycleObserver;
        }

        public final J getLifecycleOwner() {
            return this.lifecycleOwner;
        }

        public final int getMarginBottom() {
            return this.marginBottom;
        }

        public final int getMarginLeft() {
            return this.marginLeft;
        }

        public final int getMarginRight() {
            return this.marginRight;
        }

        public final int getMarginTop() {
            return this.marginTop;
        }

        public final float getMaxAutoSizeTextSize() {
            return this.maxAutoSizeTextSize;
        }

        public final int getMaxWidth() {
            return this.maxWidth;
        }

        public final float getMaxWidthRatio() {
            return this.maxWidthRatio;
        }

        public final int getMeasuredWidth() {
            return this.measuredWidth;
        }

        public final float getMinAutoSizeTextSize() {
            return this.minAutoSizeTextSize;
        }

        public final int getMinWidth() {
            return this.minWidth;
        }

        public final float getMinWidthRatio() {
            return this.minWidthRatio;
        }

        public final MovementMethod getMovementMethod() {
            return this.movementMethod;
        }

        public final OnBalloonClickListener getOnBalloonClickListener() {
            return this.onBalloonClickListener;
        }

        public final OnBalloonDismissListener getOnBalloonDismissListener() {
            return this.onBalloonDismissListener;
        }

        public final OnBalloonInitializedListener getOnBalloonInitializedListener() {
            return this.onBalloonInitializedListener;
        }

        public final OnBalloonOutsideTouchListener getOnBalloonOutsideTouchListener() {
            return this.onBalloonOutsideTouchListener;
        }

        public final OnBalloonOverlayClickListener getOnBalloonOverlayClickListener() {
            return this.onBalloonOverlayClickListener;
        }

        public final View.OnTouchListener getOnBalloonOverlayTouchListener() {
            return this.onBalloonOverlayTouchListener;
        }

        public final View.OnTouchListener getOnBalloonTouchListener() {
            return this.onBalloonTouchListener;
        }

        public final int getOverlayColor() {
            return this.overlayColor;
        }

        public final int getOverlayGravity() {
            return this.overlayGravity;
        }

        public final float getOverlayPadding() {
            return this.overlayPadding;
        }

        public final int getOverlayPaddingColor() {
            return this.overlayPaddingColor;
        }

        public final Shader getOverlayPaddingShader() {
            return this.overlayPaddingShader;
        }

        public final Point getOverlayPosition() {
            return this.overlayPosition;
        }

        @NotNull
        public final BalloonOverlayShape getOverlayShape() {
            return this.overlayShape;
        }

        public final int getPaddingBottom() {
            return this.paddingBottom;
        }

        public final int getPaddingLeft() {
            return this.paddingLeft;
        }

        public final int getPaddingRight() {
            return this.paddingRight;
        }

        public final int getPaddingTop() {
            return this.paddingTop;
        }

        public final boolean getPassTouchEventToAnchor() {
            return this.passTouchEventToAnchor;
        }

        public final String getPreferenceName() {
            return this.preferenceName;
        }

        public final Function0<Unit> getRunIfReachedShowCounts() {
            return this.runIfReachedShowCounts;
        }

        public final int getShowTimes() {
            return this.showTimes;
        }

        public final int getSupportRtlLayoutFactor() {
            return this.supportRtlLayoutFactor;
        }

        @NotNull
        public final CharSequence getText() {
            return this.text;
        }

        public final int getTextColor() {
            return this.textColor;
        }

        public final TextForm getTextForm() {
            return this.textForm;
        }

        public final int getTextGravity() {
            return this.textGravity;
        }

        public final boolean getTextIsHtml() {
            return this.textIsHtml;
        }

        public final Float getTextLetterSpacing() {
            return this.textLetterSpacing;
        }

        public final Float getTextLineSpacing() {
            return this.textLineSpacing;
        }

        public final float getTextSize() {
            return this.textSize;
        }

        public final int getTextTypeface() {
            return this.textTypeface;
        }

        public final Typeface getTextTypefaceObject() {
            return this.textTypefaceObject;
        }

        public final int getWidth() {
            return this.width;
        }

        public final float getWidthRatio() {
            return this.widthRatio;
        }

        public final boolean isAttachedInDecor() {
            return this.isAttachedInDecor;
        }

        public final boolean isComposableContent() {
            return this.isComposableContent;
        }

        public final boolean isFocusable() {
            return this.isFocusable;
        }

        public final boolean isRtlLayout() {
            return this.isRtlLayout;
        }

        public final boolean isStatusBarVisible() {
            return this.isStatusBarVisible;
        }

        public final boolean isVisibleArrow() {
            return this.isVisibleArrow;
        }

        public final boolean isVisibleOverlay() {
            return this.isVisibleOverlay;
        }

        @NotNull
        public final Builder runIfReachedShowCounts(@NotNull Function0<Unit> block) {
            Intrinsics.checkNotNullParameter(block, "block");
            this.runIfReachedShowCounts = block;
            return this;
        }

        /* renamed from: setAlpha, reason: collision with other method in class */
        public final /* synthetic */ void m35setAlpha(float f) {
            this.alpha = f;
        }

        @NotNull
        public final Builder setArrowAlignAnchorPadding(@Dp int i) {
            this.arrowAlignAnchorPadding = AbstractC4178x.a(i, 1);
            return this;
        }

        /* renamed from: setArrowAlignAnchorPaddingRatio, reason: collision with other method in class */
        public final /* synthetic */ void m37setArrowAlignAnchorPaddingRatio(float f) {
            this.arrowAlignAnchorPaddingRatio = f;
        }

        @NotNull
        public final Builder setArrowAlignAnchorPaddingResource(int i) {
            this.arrowAlignAnchorPadding = ContextExtensionKt.dimenPixel(this.context, i);
            return this;
        }

        @NotNull
        public final Builder setArrowBottomPadding(@Dp int i) {
            this.arrowBottomPadding = AbstractC4178x.a(i, 1);
            return this;
        }

        @NotNull
        public final Builder setArrowBottomPaddingResource(int i) {
            this.arrowBottomPadding = ContextExtensionKt.dimenPixel(this.context, i);
            return this;
        }

        /* renamed from: setArrowColor, reason: collision with other method in class */
        public final /* synthetic */ void m39setArrowColor(int i) {
            this.arrowColor = i;
        }

        /* renamed from: setArrowColorMatchBalloon, reason: collision with other method in class */
        public final /* synthetic */ void m40setArrowColorMatchBalloon(boolean z) {
            this.arrowColorMatchBalloon = z;
        }

        @NotNull
        public final Builder setArrowColorResource(int i) {
            this.arrowColor = ContextExtensionKt.contextColor(this.context, i);
            return this;
        }

        /* renamed from: setArrowDrawable, reason: collision with other method in class */
        public final /* synthetic */ void m41setArrowDrawable(Drawable drawable) {
            this.arrowDrawable = drawable;
        }

        @NotNull
        public final Builder setArrowDrawableResource(int i) {
            setArrowDrawable(ContextExtensionKt.contextDrawable(this.context, i));
            return this;
        }

        @NotNull
        public final Builder setArrowElevation(@Dp int i) {
            this.arrowElevation = AbstractC4178x.a(i, 1);
            return this;
        }

        @NotNull
        public final Builder setArrowElevationResource(int i) {
            this.arrowElevation = ContextExtensionKt.dimen(this.context, i);
            return this;
        }

        @NotNull
        public final Builder setArrowLeftPadding(@Dp int i) {
            this.arrowLeftPadding = AbstractC4178x.a(i, 1);
            return this;
        }

        @NotNull
        public final Builder setArrowLeftPaddingResource(int i) {
            this.arrowLeftPadding = ContextExtensionKt.dimenPixel(this.context, i);
            return this;
        }

        /* renamed from: setArrowOrientation, reason: collision with other method in class */
        public final /* synthetic */ void m43setArrowOrientation(ArrowOrientation arrowOrientation) {
            Intrinsics.checkNotNullParameter(arrowOrientation, "<set-?>");
            this.arrowOrientation = arrowOrientation;
        }

        /* renamed from: setArrowOrientationRules, reason: collision with other method in class */
        public final /* synthetic */ void m44setArrowOrientationRules(ArrowOrientationRules arrowOrientationRules) {
            Intrinsics.checkNotNullParameter(arrowOrientationRules, "<set-?>");
            this.arrowOrientationRules = arrowOrientationRules;
        }

        /* renamed from: setArrowPosition, reason: collision with other method in class */
        public final /* synthetic */ void m45setArrowPosition(float f) {
            this.arrowPosition = f;
        }

        /* renamed from: setArrowPositionRules, reason: collision with other method in class */
        public final /* synthetic */ void m46setArrowPositionRules(ArrowPositionRules arrowPositionRules) {
            Intrinsics.checkNotNullParameter(arrowPositionRules, "<set-?>");
            this.arrowPositionRules = arrowPositionRules;
        }

        @NotNull
        public final Builder setArrowRightPadding(@Dp int i) {
            this.arrowRightPadding = AbstractC4178x.a(i, 1);
            return this;
        }

        @NotNull
        public final Builder setArrowRightPaddingResource(int i) {
            this.arrowRightPadding = ContextExtensionKt.dimenPixel(this.context, i);
            return this;
        }

        @NotNull
        public final Builder setArrowSize(@Dp int i) {
            this.arrowSize = i != Integer.MIN_VALUE ? AbstractC4178x.a(i, 1) : Integer.MIN_VALUE;
            return this;
        }

        @NotNull
        public final Builder setArrowSizeResource(int i) {
            this.arrowSize = ContextExtensionKt.dimenPixel(this.context, i);
            return this;
        }

        @NotNull
        public final Builder setArrowTopPadding(@Dp int i) {
            this.arrowTopPadding = AbstractC4178x.a(i, 1);
            return this;
        }

        @NotNull
        public final Builder setArrowTopPaddingResource(int i) {
            this.arrowTopPadding = ContextExtensionKt.dimenPixel(this.context, i);
            return this;
        }

        public final /* synthetic */ void setAttachedInDecor(boolean z) {
            this.isAttachedInDecor = z;
        }

        /* renamed from: setAutoDismissDuration, reason: collision with other method in class */
        public final /* synthetic */ void m50setAutoDismissDuration(long j) {
            this.autoDismissDuration = j;
        }

        /* renamed from: setBackgroundColor, reason: collision with other method in class */
        public final /* synthetic */ void m51setBackgroundColor(int i) {
            this.backgroundColor = i;
        }

        @NotNull
        public final Builder setBackgroundColorResource(int i) {
            this.backgroundColor = ContextExtensionKt.contextColor(this.context, i);
            return this;
        }

        /* renamed from: setBackgroundDrawable, reason: collision with other method in class */
        public final /* synthetic */ void m52setBackgroundDrawable(Drawable drawable) {
            this.backgroundDrawable = drawable;
        }

        @NotNull
        public final Builder setBackgroundDrawableResource(int i) {
            Drawable drawableContextDrawable = ContextExtensionKt.contextDrawable(this.context, i);
            this.backgroundDrawable = drawableContextDrawable != null ? drawableContextDrawable.mutate() : null;
            return this;
        }

        /* renamed from: setBalloonAnimation, reason: collision with other method in class */
        public final /* synthetic */ void m53setBalloonAnimation(BalloonAnimation balloonAnimation) {
            Intrinsics.checkNotNullParameter(balloonAnimation, "<set-?>");
            this.balloonAnimation = balloonAnimation;
        }

        /* renamed from: setBalloonAnimationStyle, reason: collision with other method in class */
        public final /* synthetic */ void m54setBalloonAnimationStyle(int i) {
            this.balloonAnimationStyle = i;
        }

        @NotNull
        public final Builder setBalloonHighlightAnimation(@NotNull BalloonHighlightAnimation value) {
            Intrinsics.checkNotNullParameter(value, "value");
            return setBalloonHighlightAnimation$default(this, value, 0L, 2, null);
        }

        @NotNull
        public final Builder setBalloonHighlightAnimationResource(int i) {
            return setBalloonHighlightAnimationResource$default(this, i, 0L, 2, null);
        }

        public final /* synthetic */ void setBalloonHighlightAnimationStartDelay(long j) {
            this.balloonHighlightAnimationStartDelay = j;
        }

        public final /* synthetic */ void setBalloonHighlightAnimationStyle(int i) {
            this.balloonHighlightAnimationStyle = i;
        }

        /* renamed from: setBalloonOverlayAnimation, reason: collision with other method in class */
        public final /* synthetic */ void m56setBalloonOverlayAnimation(BalloonOverlayAnimation balloonOverlayAnimation) {
            Intrinsics.checkNotNullParameter(balloonOverlayAnimation, "<set-?>");
            this.balloonOverlayAnimation = balloonOverlayAnimation;
        }

        /* renamed from: setBalloonOverlayAnimationStyle, reason: collision with other method in class */
        public final /* synthetic */ void m57setBalloonOverlayAnimationStyle(int i) {
            this.balloonOverlayAnimationStyle = i;
        }

        public final /* synthetic */ void setBalloonRotateAnimation(BalloonRotateAnimation balloonRotateAnimation) {
            this.balloonRotateAnimation = balloonRotateAnimation;
        }

        @NotNull
        public final Builder setBalloonRotationAnimation(@NotNull BalloonRotateAnimation balloonRotateAnimation) {
            Intrinsics.checkNotNullParameter(balloonRotateAnimation, "balloonRotateAnimation");
            this.balloonRotateAnimation = balloonRotateAnimation;
            return this;
        }

        /* renamed from: setCircularDuration, reason: collision with other method in class */
        public final /* synthetic */ void m58setCircularDuration(long j) {
            this.circularDuration = j;
        }

        public final /* synthetic */ void setComposableContent(boolean z) {
            this.isComposableContent = z;
        }

        /* renamed from: setCornerRadius, reason: collision with other method in class */
        public final /* synthetic */ void m59setCornerRadius(float f) {
            this.cornerRadius = f;
        }

        @NotNull
        public final Builder setCornerRadiusResource(int i) {
            this.cornerRadius = ContextExtensionKt.dimen(this.context, i);
            return this;
        }

        /* renamed from: setDismissWhenClicked, reason: collision with other method in class */
        public final /* synthetic */ void m60setDismissWhenClicked(boolean z) {
            this.dismissWhenClicked = z;
        }

        /* renamed from: setDismissWhenLifecycleOnPause, reason: collision with other method in class */
        public final /* synthetic */ void m61setDismissWhenLifecycleOnPause(boolean z) {
            this.dismissWhenLifecycleOnPause = z;
        }

        /* renamed from: setDismissWhenOverlayClicked, reason: collision with other method in class */
        public final /* synthetic */ void m62setDismissWhenOverlayClicked(boolean z) {
            this.dismissWhenOverlayClicked = z;
        }

        /* renamed from: setDismissWhenShowAgain, reason: collision with other method in class */
        public final /* synthetic */ void m63setDismissWhenShowAgain(boolean z) {
            this.dismissWhenShowAgain = z;
        }

        /* renamed from: setDismissWhenTouchMargin, reason: collision with other method in class */
        public final /* synthetic */ void m64setDismissWhenTouchMargin(boolean z) {
            this.dismissWhenTouchMargin = z;
        }

        /* renamed from: setDismissWhenTouchOutside, reason: collision with other method in class */
        public final /* synthetic */ void m65setDismissWhenTouchOutside(boolean z) {
            this.dismissWhenTouchOutside = z;
        }

        @NotNull
        public final Builder setElevation(@Dp int i) {
            this.elevation = AbstractC4178x.a(i, 1);
            return this;
        }

        @NotNull
        public final Builder setElevationResource(int i) {
            this.elevation = ContextExtensionKt.dimen(this.context, i);
            return this;
        }

        /* renamed from: setEnableAutoSized, reason: collision with other method in class */
        public final /* synthetic */ void m66setEnableAutoSized(boolean z) {
            this.enableAutoSized = z;
        }

        /* renamed from: setFocusable, reason: collision with other method in class */
        public final /* synthetic */ void m67setFocusable(boolean z) {
            this.isFocusable = z;
        }

        /* renamed from: setHeight, reason: collision with other method in class */
        public final /* synthetic */ void m68setHeight(int i) {
            this.height = i;
        }

        @NotNull
        public final Builder setHeightResource(int i) {
            this.height = ContextExtensionKt.dimenPixel(this.context, i);
            return this;
        }

        /* renamed from: setIconColor, reason: collision with other method in class */
        public final /* synthetic */ void m69setIconColor(int i) {
            this.iconColor = i;
        }

        @NotNull
        public final Builder setIconColorResource(int i) {
            this.iconColor = ContextExtensionKt.contextColor(this.context, i);
            return this;
        }

        /* renamed from: setIconContentDescription, reason: collision with other method in class */
        public final /* synthetic */ void m70setIconContentDescription(CharSequence charSequence) {
            Intrinsics.checkNotNullParameter(charSequence, "<set-?>");
            this.iconContentDescription = charSequence;
        }

        @NotNull
        public final Builder setIconContentDescriptionResource(int i) {
            this.iconContentDescription = this.context.getString(i);
            return this;
        }

        /* renamed from: setIconDrawable, reason: collision with other method in class */
        public final /* synthetic */ void m71setIconDrawable(Drawable drawable) {
            this.iconDrawable = drawable;
        }

        @NotNull
        public final Builder setIconDrawableResource(int i) {
            Drawable drawableContextDrawable = ContextExtensionKt.contextDrawable(this.context, i);
            this.iconDrawable = drawableContextDrawable != null ? drawableContextDrawable.mutate() : null;
            return this;
        }

        /* renamed from: setIconForm, reason: collision with other method in class */
        public final /* synthetic */ void m72setIconForm(IconForm iconForm) {
            this.iconForm = iconForm;
        }

        /* renamed from: setIconGravity, reason: collision with other method in class */
        public final /* synthetic */ void m73setIconGravity(IconGravity iconGravity) {
            Intrinsics.checkNotNullParameter(iconGravity, "<set-?>");
            this.iconGravity = iconGravity;
        }

        @NotNull
        public final Builder setIconHeight(@Dp int i) {
            this.iconHeight = AbstractC4178x.a(i, 1);
            return this;
        }

        @NotNull
        public final Builder setIconHeightResource(int i) {
            this.iconHeight = ContextExtensionKt.dimenPixel(this.context, i);
            return this;
        }

        @NotNull
        public final Builder setIconSize(@Dp int i) {
            setIconWidth(i);
            setIconHeight(i);
            return this;
        }

        @NotNull
        public final Builder setIconSizeResource(int i) {
            setIconWidthResource(i);
            setIconHeightResource(i);
            return this;
        }

        @NotNull
        public final Builder setIconSpace(@Dp int i) {
            this.iconSpace = AbstractC4178x.a(i, 1);
            return this;
        }

        @NotNull
        public final Builder setIconSpaceResource(int i) {
            this.iconSpace = ContextExtensionKt.dimenPixel(this.context, i);
            return this;
        }

        @NotNull
        public final Builder setIconWidth(@Dp int i) {
            this.iconWidth = AbstractC4178x.a(i, 1);
            return this;
        }

        @NotNull
        public final Builder setIconWidthResource(int i) {
            this.iconWidth = ContextExtensionKt.dimenPixel(this.context, i);
            return this;
        }

        /* renamed from: setIncludeFontPadding, reason: collision with other method in class */
        public final /* synthetic */ void m77setIncludeFontPadding(boolean z) {
            this.includeFontPadding = z;
        }

        @NotNull
        public final Builder setIsAttachedInDecor(boolean z) {
            this.isAttachedInDecor = z;
            return this;
        }

        @NotNull
        public final Builder setIsComposableContent(boolean z) {
            this.isComposableContent = z;
            return this;
        }

        @NotNull
        public final Builder setIsStatusBarVisible(boolean z) {
            this.isStatusBarVisible = z;
            return this;
        }

        @NotNull
        public final Builder setIsVisibleArrow(boolean z) {
            this.isVisibleArrow = z;
            return this;
        }

        @NotNull
        public final Builder setIsVisibleOverlay(boolean z) {
            this.isVisibleOverlay = z;
            return this;
        }

        /* renamed from: setLayout, reason: collision with other method in class */
        public final /* synthetic */ void m78setLayout(View view) {
            this.layout = view;
        }

        public final /* synthetic */ void setLayoutRes(Integer num) {
            this.layoutRes = num;
        }

        /* renamed from: setLifecycleObserver, reason: collision with other method in class */
        public final /* synthetic */ void m79setLifecycleObserver(I i) {
            this.lifecycleObserver = i;
        }

        /* renamed from: setLifecycleOwner, reason: collision with other method in class */
        public final /* synthetic */ void m80setLifecycleOwner(J j) {
            this.lifecycleOwner = j;
        }

        @NotNull
        public final Builder setMargin(@Dp int i) {
            setMarginLeft(i);
            setMarginTop(i);
            setMarginRight(i);
            setMarginBottom(i);
            return this;
        }

        @NotNull
        public final Builder setMarginBottom(@Dp int i) {
            this.marginBottom = AbstractC4178x.a(i, 1);
            return this;
        }

        @NotNull
        public final Builder setMarginBottomResource(int i) {
            this.marginBottom = ContextExtensionKt.dimenPixel(this.context, i);
            return this;
        }

        @NotNull
        public final Builder setMarginHorizontal(@Dp int i) {
            setMarginLeft(i);
            setMarginRight(i);
            return this;
        }

        @NotNull
        public final Builder setMarginHorizontalResource(int i) {
            setMarginLeftResource(i);
            setMarginRightResource(i);
            return this;
        }

        @NotNull
        public final Builder setMarginLeft(@Dp int i) {
            this.marginLeft = AbstractC4178x.a(i, 1);
            return this;
        }

        @NotNull
        public final Builder setMarginLeftResource(int i) {
            this.marginLeft = ContextExtensionKt.dimenPixel(this.context, i);
            return this;
        }

        @NotNull
        public final Builder setMarginResource(int i) {
            int iDimenPixel = ContextExtensionKt.dimenPixel(this.context, i);
            this.marginLeft = iDimenPixel;
            this.marginTop = iDimenPixel;
            this.marginRight = iDimenPixel;
            this.marginBottom = iDimenPixel;
            return this;
        }

        @NotNull
        public final Builder setMarginRight(@Dp int i) {
            this.marginRight = AbstractC4178x.a(i, 1);
            return this;
        }

        @NotNull
        public final Builder setMarginRightResource(int i) {
            this.marginRight = ContextExtensionKt.dimenPixel(this.context, i);
            return this;
        }

        @NotNull
        public final Builder setMarginTop(@Dp int i) {
            this.marginTop = AbstractC4178x.a(i, 1);
            return this;
        }

        @NotNull
        public final Builder setMarginTopResource(int i) {
            this.marginTop = ContextExtensionKt.dimenPixel(this.context, i);
            return this;
        }

        @NotNull
        public final Builder setMarginVertical(@Dp int i) {
            setMarginTop(i);
            setMarginBottom(i);
            return this;
        }

        @NotNull
        public final Builder setMarginVerticalResource(int i) {
            setMarginTopResource(i);
            setMarginBottomResource(i);
            return this;
        }

        /* renamed from: setMaxAutoSizeTextSize, reason: collision with other method in class */
        public final /* synthetic */ void m85setMaxAutoSizeTextSize(float f) {
            this.maxAutoSizeTextSize = f;
        }

        @NotNull
        public final Builder setMaxWidth(@Dp int i) {
            this.maxWidth = AbstractC4178x.a(i, 1);
            return this;
        }

        /* renamed from: setMaxWidthRatio, reason: collision with other method in class */
        public final /* synthetic */ void m87setMaxWidthRatio(float f) {
            this.maxWidthRatio = f;
        }

        @NotNull
        public final Builder setMaxWidthResource(int i) {
            this.maxWidth = ContextExtensionKt.dimenPixel(this.context, i);
            return this;
        }

        /* renamed from: setMeasuredWidth, reason: collision with other method in class */
        public final /* synthetic */ void m88setMeasuredWidth(int i) {
            this.measuredWidth = i;
        }

        /* renamed from: setMinAutoSizeTextSize, reason: collision with other method in class */
        public final /* synthetic */ void m89setMinAutoSizeTextSize(float f) {
            this.minAutoSizeTextSize = f;
        }

        @NotNull
        public final Builder setMinWidth(@Dp int i) {
            this.minWidth = AbstractC4178x.a(i, 1);
            return this;
        }

        /* renamed from: setMinWidthRatio, reason: collision with other method in class */
        public final /* synthetic */ void m91setMinWidthRatio(float f) {
            this.minWidthRatio = f;
        }

        @NotNull
        public final Builder setMinWidthResource(int i) {
            this.minWidth = ContextExtensionKt.dimenPixel(this.context, i);
            return this;
        }

        /* renamed from: setMovementMethod, reason: collision with other method in class */
        public final /* synthetic */ void m92setMovementMethod(MovementMethod movementMethod) {
            this.movementMethod = movementMethod;
        }

        /* renamed from: setOnBalloonClickListener, reason: collision with other method in class */
        public final /* synthetic */ void m93setOnBalloonClickListener(OnBalloonClickListener onBalloonClickListener) {
            this.onBalloonClickListener = onBalloonClickListener;
        }

        /* renamed from: setOnBalloonDismissListener, reason: collision with other method in class */
        public final /* synthetic */ void m94setOnBalloonDismissListener(OnBalloonDismissListener onBalloonDismissListener) {
            this.onBalloonDismissListener = onBalloonDismissListener;
        }

        /* renamed from: setOnBalloonInitializedListener, reason: collision with other method in class */
        public final /* synthetic */ void m95setOnBalloonInitializedListener(OnBalloonInitializedListener onBalloonInitializedListener) {
            this.onBalloonInitializedListener = onBalloonInitializedListener;
        }

        /* renamed from: setOnBalloonOutsideTouchListener, reason: collision with other method in class */
        public final /* synthetic */ void m96setOnBalloonOutsideTouchListener(OnBalloonOutsideTouchListener onBalloonOutsideTouchListener) {
            this.onBalloonOutsideTouchListener = onBalloonOutsideTouchListener;
        }

        /* renamed from: setOnBalloonOverlayClickListener, reason: collision with other method in class */
        public final /* synthetic */ void m97setOnBalloonOverlayClickListener(OnBalloonOverlayClickListener onBalloonOverlayClickListener) {
            this.onBalloonOverlayClickListener = onBalloonOverlayClickListener;
        }

        /* renamed from: setOnBalloonOverlayTouchListener, reason: collision with other method in class */
        public final /* synthetic */ void m98setOnBalloonOverlayTouchListener(View.OnTouchListener onTouchListener) {
            this.onBalloonOverlayTouchListener = onTouchListener;
        }

        /* renamed from: setOnBalloonTouchListener, reason: collision with other method in class */
        public final /* synthetic */ void m99setOnBalloonTouchListener(View.OnTouchListener onTouchListener) {
            this.onBalloonTouchListener = onTouchListener;
        }

        /* renamed from: setOverlayColor, reason: collision with other method in class */
        public final /* synthetic */ void m100setOverlayColor(int i) {
            this.overlayColor = i;
        }

        @NotNull
        public final Builder setOverlayColorResource(int i) {
            this.overlayColor = ContextExtensionKt.contextColor(this.context, i);
            return this;
        }

        /* renamed from: setOverlayGravity, reason: collision with other method in class */
        public final /* synthetic */ void m101setOverlayGravity(int i) {
            this.overlayGravity = i;
        }

        /* renamed from: setOverlayPadding, reason: collision with other method in class */
        public final /* synthetic */ void m102setOverlayPadding(float f) {
            this.overlayPadding = f;
        }

        /* renamed from: setOverlayPaddingColor, reason: collision with other method in class */
        public final /* synthetic */ void m103setOverlayPaddingColor(int i) {
            this.overlayPaddingColor = i;
        }

        @NotNull
        public final Builder setOverlayPaddingColorResource(int i) {
            this.overlayPaddingColor = ContextExtensionKt.contextColor(this.context, i);
            return this;
        }

        @NotNull
        public final Builder setOverlayPaddingResource(int i) {
            this.overlayPadding = ContextExtensionKt.dimen(this.context, i);
            return this;
        }

        /* renamed from: setOverlayPaddingShader, reason: collision with other method in class */
        public final /* synthetic */ void m104setOverlayPaddingShader(Shader shader) {
            this.overlayPaddingShader = shader;
        }

        /* renamed from: setOverlayPosition, reason: collision with other method in class */
        public final /* synthetic */ void m105setOverlayPosition(Point point) {
            this.overlayPosition = point;
        }

        /* renamed from: setOverlayShape, reason: collision with other method in class */
        public final /* synthetic */ void m106setOverlayShape(BalloonOverlayShape balloonOverlayShape) {
            Intrinsics.checkNotNullParameter(balloonOverlayShape, "<set-?>");
            this.overlayShape = balloonOverlayShape;
        }

        @NotNull
        public final Builder setPadding(@Dp int i) {
            setPaddingLeft(i);
            setPaddingTop(i);
            setPaddingRight(i);
            setPaddingBottom(i);
            return this;
        }

        @NotNull
        public final Builder setPaddingBottom(@Dp int i) {
            this.paddingBottom = AbstractC4178x.a(i, 1);
            return this;
        }

        @NotNull
        public final Builder setPaddingBottomResource(int i) {
            this.paddingBottom = ContextExtensionKt.dimenPixel(this.context, i);
            return this;
        }

        @NotNull
        public final Builder setPaddingHorizontal(@Dp int i) {
            setPaddingLeft(i);
            setPaddingRight(i);
            return this;
        }

        @NotNull
        public final Builder setPaddingHorizontalResource(int i) {
            setPaddingLeftResource(i);
            setPaddingRightResource(i);
            return this;
        }

        @NotNull
        public final Builder setPaddingLeft(@Dp int i) {
            this.paddingLeft = AbstractC4178x.a(i, 1);
            return this;
        }

        @NotNull
        public final Builder setPaddingLeftResource(int i) {
            this.paddingLeft = ContextExtensionKt.dimenPixel(this.context, i);
            return this;
        }

        @NotNull
        public final Builder setPaddingResource(int i) {
            int iDimenPixel = ContextExtensionKt.dimenPixel(this.context, i);
            this.paddingLeft = iDimenPixel;
            this.paddingTop = iDimenPixel;
            this.paddingRight = iDimenPixel;
            this.paddingBottom = iDimenPixel;
            return this;
        }

        @NotNull
        public final Builder setPaddingRight(@Dp int i) {
            this.paddingRight = AbstractC4178x.a(i, 1);
            return this;
        }

        @NotNull
        public final Builder setPaddingRightResource(int i) {
            this.paddingRight = ContextExtensionKt.dimenPixel(this.context, i);
            return this;
        }

        @NotNull
        public final Builder setPaddingTop(@Dp int i) {
            this.paddingTop = AbstractC4178x.a(i, 1);
            return this;
        }

        @NotNull
        public final Builder setPaddingTopResource(int i) {
            this.paddingTop = ContextExtensionKt.dimenPixel(this.context, i);
            return this;
        }

        @NotNull
        public final Builder setPaddingVertical(@Dp int i) {
            setPaddingTop(i);
            setPaddingBottom(i);
            return this;
        }

        @NotNull
        public final Builder setPaddingVerticalResource(int i) {
            setPaddingTopResource(i);
            setPaddingBottomResource(i);
            return this;
        }

        public final /* synthetic */ void setPassTouchEventToAnchor(boolean z) {
            this.passTouchEventToAnchor = z;
        }

        /* renamed from: setPreferenceName, reason: collision with other method in class */
        public final /* synthetic */ void m111setPreferenceName(String str) {
            this.preferenceName = str;
        }

        public final /* synthetic */ void setRtlLayout(boolean z) {
            this.isRtlLayout = z;
        }

        @NotNull
        public final Builder setRtlSupports(boolean z) {
            this.isRtlLayout = z;
            return this;
        }

        public final /* synthetic */ void setRunIfReachedShowCounts(Function0 function0) {
            this.runIfReachedShowCounts = function0;
        }

        @NotNull
        public final Builder setShouldPassTouchEventToAnchor(boolean z) {
            this.passTouchEventToAnchor = z;
            return this;
        }

        @NotNull
        public final Builder setShowCounts(int i) {
            this.showTimes = i;
            return this;
        }

        public final /* synthetic */ void setShowTimes(int i) {
            this.showTimes = i;
        }

        @NotNull
        public final Builder setSize(@Dp int i, @Dp int i2) {
            setWidth(i);
            setHeight(i2);
            return this;
        }

        @NotNull
        public final Builder setSizeResource(int i, int i2) {
            setWidthResource(i);
            setHeightResource(i2);
            return this;
        }

        public final /* synthetic */ void setStatusBarVisible(boolean z) {
            this.isStatusBarVisible = z;
        }

        public final /* synthetic */ void setSupportRtlLayoutFactor(int i) {
            this.supportRtlLayoutFactor = i;
        }

        /* renamed from: setText, reason: collision with other method in class */
        public final /* synthetic */ void m112setText(CharSequence charSequence) {
            Intrinsics.checkNotNullParameter(charSequence, "<set-?>");
            this.text = charSequence;
        }

        /* renamed from: setTextColor, reason: collision with other method in class */
        public final /* synthetic */ void m113setTextColor(int i) {
            this.textColor = i;
        }

        @NotNull
        public final Builder setTextColorResource(int i) {
            this.textColor = ContextExtensionKt.contextColor(this.context, i);
            return this;
        }

        /* renamed from: setTextForm, reason: collision with other method in class */
        public final /* synthetic */ void m114setTextForm(TextForm textForm) {
            this.textForm = textForm;
        }

        /* renamed from: setTextGravity, reason: collision with other method in class */
        public final /* synthetic */ void m115setTextGravity(int i) {
            this.textGravity = i;
        }

        /* renamed from: setTextIsHtml, reason: collision with other method in class */
        public final /* synthetic */ void m116setTextIsHtml(boolean z) {
            this.textIsHtml = z;
        }

        public final /* synthetic */ void setTextLetterSpacing(Float f) {
            this.textLetterSpacing = f;
        }

        @NotNull
        public final Builder setTextLetterSpacingResource(int i) {
            this.textLetterSpacing = Float.valueOf(ContextExtensionKt.dimen(this.context, i));
            return this;
        }

        public final /* synthetic */ void setTextLineSpacing(Float f) {
            this.textLineSpacing = f;
        }

        @NotNull
        public final Builder setTextLineSpacingResource(int i) {
            this.textLineSpacing = Float.valueOf(ContextExtensionKt.dimen(this.context, i));
            return this;
        }

        @NotNull
        public final Builder setTextResource(int i) {
            this.text = this.context.getString(i);
            return this;
        }

        /* renamed from: setTextSize, reason: collision with other method in class */
        public final /* synthetic */ void m117setTextSize(float f) {
            this.textSize = f;
        }

        @NotNull
        public final Builder setTextSizeResource(int i) {
            Context context = this.context;
            this.textSize = ContextExtensionKt.px2Sp(context, ContextExtensionKt.dimen(context, i));
            return this;
        }

        /* renamed from: setTextTypeface, reason: collision with other method in class */
        public final /* synthetic */ void m118setTextTypeface(int i) {
            this.textTypeface = i;
        }

        public final /* synthetic */ void setTextTypefaceObject(Typeface typeface) {
            this.textTypefaceObject = typeface;
        }

        public final /* synthetic */ void setVisibleArrow(boolean z) {
            this.isVisibleArrow = z;
        }

        public final /* synthetic */ void setVisibleOverlay(boolean z) {
            this.isVisibleOverlay = z;
        }

        /* renamed from: setWidth, reason: collision with other method in class */
        public final /* synthetic */ void m119setWidth(int i) {
            this.width = i;
        }

        /* renamed from: setWidthRatio, reason: collision with other method in class */
        public final /* synthetic */ void m120setWidthRatio(float f) {
            this.widthRatio = f;
        }

        @NotNull
        public final Builder setWidthResource(int i) {
            this.width = ContextExtensionKt.dimenPixel(this.context, i);
            return this;
        }

        @NotNull
        public final Builder runIfReachedShowCounts(@NotNull Runnable runnable) {
            Intrinsics.checkNotNullParameter(runnable, "runnable");
            runIfReachedShowCounts(new com.quizlet.quizletandroid.ui.studymodes.assistant.settings.grading.a(runnable, 17));
            return this;
        }

        @NotNull
        public final Builder setAlpha(float f) {
            this.alpha = f;
            return this;
        }

        @NotNull
        public final Builder setArrowAlignAnchorPaddingRatio(float f) {
            this.arrowAlignAnchorPaddingRatio = f;
            return this;
        }

        @NotNull
        public final Builder setArrowColor(int i) {
            this.arrowColor = i;
            return this;
        }

        @NotNull
        public final Builder setArrowColorMatchBalloon(boolean z) {
            this.arrowColorMatchBalloon = z;
            return this;
        }

        @NotNull
        public final Builder setArrowDrawable(Drawable drawable) {
            this.arrowDrawable = drawable != null ? drawable.mutate() : null;
            if (drawable != null && this.arrowSize == Integer.MIN_VALUE) {
                this.arrowSize = Math.max(drawable.getIntrinsicWidth(), drawable.getIntrinsicHeight());
            }
            return this;
        }

        @NotNull
        public final Builder setArrowOrientation(@NotNull ArrowOrientation value) {
            Intrinsics.checkNotNullParameter(value, "value");
            this.arrowOrientation = value;
            return this;
        }

        @NotNull
        public final Builder setArrowOrientationRules(@NotNull ArrowOrientationRules value) {
            Intrinsics.checkNotNullParameter(value, "value");
            this.arrowOrientationRules = value;
            return this;
        }

        @NotNull
        public final Builder setArrowPosition(float f) {
            this.arrowPosition = f;
            return this;
        }

        @NotNull
        public final Builder setArrowPositionRules(@NotNull ArrowPositionRules value) {
            Intrinsics.checkNotNullParameter(value, "value");
            this.arrowPositionRules = value;
            return this;
        }

        @NotNull
        public final Builder setAutoDismissDuration(long j) {
            this.autoDismissDuration = j;
            return this;
        }

        @NotNull
        public final Builder setBackgroundColor(int i) {
            this.backgroundColor = i;
            return this;
        }

        @NotNull
        public final Builder setBackgroundDrawable(Drawable drawable) {
            this.backgroundDrawable = drawable != null ? drawable.mutate() : null;
            return this;
        }

        @NotNull
        public final Builder setBalloonAnimation(@NotNull BalloonAnimation value) {
            Intrinsics.checkNotNullParameter(value, "value");
            this.balloonAnimation = value;
            if (value == BalloonAnimation.CIRCULAR) {
                setFocusable(false);
            }
            return this;
        }

        @NotNull
        public final Builder setBalloonAnimationStyle(int i) {
            this.balloonAnimationStyle = i;
            return this;
        }

        /* renamed from: setBalloonHighlightAnimation, reason: collision with other method in class */
        public final /* synthetic */ void m55setBalloonHighlightAnimation(BalloonHighlightAnimation balloonHighlightAnimation) {
            Intrinsics.checkNotNullParameter(balloonHighlightAnimation, "<set-?>");
            this.balloonHighlightAnimation = balloonHighlightAnimation;
        }

        @NotNull
        public final Builder setBalloonHighlightAnimationResource(int i, long j) {
            this.balloonHighlightAnimationStyle = i;
            this.balloonHighlightAnimationStartDelay = j;
            return this;
        }

        @NotNull
        public final Builder setBalloonOverlayAnimation(@NotNull BalloonOverlayAnimation value) {
            Intrinsics.checkNotNullParameter(value, "value");
            this.balloonOverlayAnimation = value;
            return this;
        }

        @NotNull
        public final Builder setBalloonOverlayAnimationStyle(int i) {
            this.balloonOverlayAnimationStyle = i;
            return this;
        }

        @NotNull
        public final Builder setCircularDuration(long j) {
            this.circularDuration = j;
            return this;
        }

        @NotNull
        public final Builder setCornerRadius(@Dp float f) {
            this.cornerRadius = TypedValue.applyDimension(1, f, Resources.getSystem().getDisplayMetrics());
            return this;
        }

        @NotNull
        public final Builder setDismissWhenClicked(boolean z) {
            this.dismissWhenClicked = z;
            return this;
        }

        @NotNull
        public final Builder setDismissWhenLifecycleOnPause(boolean z) {
            this.dismissWhenLifecycleOnPause = z;
            return this;
        }

        @NotNull
        public final Builder setDismissWhenOverlayClicked(boolean z) {
            this.dismissWhenOverlayClicked = z;
            return this;
        }

        @NotNull
        public final Builder setDismissWhenShowAgain(boolean z) {
            this.dismissWhenShowAgain = z;
            return this;
        }

        @NotNull
        public final Builder setDismissWhenTouchMargin(boolean z) {
            this.dismissWhenTouchMargin = z;
            return this;
        }

        @NotNull
        public final Builder setDismissWhenTouchOutside(boolean z) {
            this.dismissWhenTouchOutside = z;
            if (!z) {
                setFocusable(z);
            }
            return this;
        }

        @NotNull
        public final Builder setEnableAutoSized(boolean z) {
            this.enableAutoSized = z;
            return this;
        }

        @NotNull
        public final Builder setFocusable(boolean z) {
            this.isFocusable = z;
            return this;
        }

        @NotNull
        public final Builder setHeight(@Dp int i) {
            if (i <= 0 && i != Integer.MIN_VALUE) {
                throw new IllegalArgumentException("The height of the balloon must bigger than zero.");
            }
            this.height = AbstractC4178x.a(i, 1);
            return this;
        }

        @NotNull
        public final Builder setIconColor(int i) {
            this.iconColor = i;
            return this;
        }

        @NotNull
        public final Builder setIconContentDescription(@NotNull CharSequence value) {
            Intrinsics.checkNotNullParameter(value, "value");
            this.iconContentDescription = value;
            return this;
        }

        @NotNull
        public final Builder setIconDrawable(Drawable drawable) {
            this.iconDrawable = drawable != null ? drawable.mutate() : null;
            return this;
        }

        @NotNull
        public final Builder setIconForm(@NotNull IconForm value) {
            Intrinsics.checkNotNullParameter(value, "value");
            this.iconForm = value;
            return this;
        }

        @NotNull
        public final Builder setIconGravity(@NotNull IconGravity value) {
            Intrinsics.checkNotNullParameter(value, "value");
            this.iconGravity = value;
            return this;
        }

        @NotNull
        public final Builder setIncludeFontPadding(boolean z) {
            this.includeFontPadding = z;
            return this;
        }

        @NotNull
        public final Builder setLayout(int i) {
            this.layoutRes = Integer.valueOf(i);
            return this;
        }

        @NotNull
        public final Builder setLifecycleObserver(@NotNull I value) {
            Intrinsics.checkNotNullParameter(value, "value");
            this.lifecycleObserver = value;
            return this;
        }

        @NotNull
        public final Builder setLifecycleOwner(J j) {
            this.lifecycleOwner = j;
            return this;
        }

        @NotNull
        public final Builder setMaxAutoSizeTextSize(@Sp float f) {
            this.maxAutoSizeTextSize = f;
            return this;
        }

        @NotNull
        public final Builder setMaxWidthRatio(float f) {
            this.maxWidthRatio = f;
            return this;
        }

        @NotNull
        public final Builder setMeasuredWidth(int i) {
            if (i <= 0 && i != Integer.MIN_VALUE) {
                throw new IllegalArgumentException("The width of the balloon must bigger than zero.");
            }
            this.measuredWidth = i;
            return this;
        }

        @NotNull
        public final Builder setMinAutoSizeTextSize(@Sp float f) {
            this.minAutoSizeTextSize = f;
            return this;
        }

        @NotNull
        public final Builder setMinWidthRatio(float f) {
            this.minWidthRatio = f;
            return this;
        }

        @NotNull
        public final Builder setMovementMethod(@NotNull MovementMethod value) {
            Intrinsics.checkNotNullParameter(value, "value");
            this.movementMethod = value;
            return this;
        }

        @NotNull
        public final Builder setOnBalloonClickListener(@NotNull OnBalloonClickListener value) {
            Intrinsics.checkNotNullParameter(value, "value");
            this.onBalloonClickListener = value;
            return this;
        }

        @NotNull
        public final Builder setOnBalloonDismissListener(@NotNull OnBalloonDismissListener value) {
            Intrinsics.checkNotNullParameter(value, "value");
            this.onBalloonDismissListener = value;
            return this;
        }

        @NotNull
        public final Builder setOnBalloonInitializedListener(@NotNull OnBalloonInitializedListener value) {
            Intrinsics.checkNotNullParameter(value, "value");
            this.onBalloonInitializedListener = value;
            return this;
        }

        @NotNull
        public final Builder setOnBalloonOutsideTouchListener(@NotNull OnBalloonOutsideTouchListener value) {
            Intrinsics.checkNotNullParameter(value, "value");
            this.onBalloonOutsideTouchListener = value;
            return this;
        }

        @NotNull
        public final Builder setOnBalloonOverlayClickListener(@NotNull OnBalloonOverlayClickListener value) {
            Intrinsics.checkNotNullParameter(value, "value");
            this.onBalloonOverlayClickListener = value;
            return this;
        }

        @NotNull
        public final Builder setOnBalloonOverlayTouchListener(@NotNull View.OnTouchListener value) {
            Intrinsics.checkNotNullParameter(value, "value");
            this.onBalloonOverlayTouchListener = value;
            setDismissWhenOverlayClicked(false);
            return this;
        }

        @NotNull
        public final Builder setOnBalloonTouchListener(@NotNull View.OnTouchListener value) {
            Intrinsics.checkNotNullParameter(value, "value");
            this.onBalloonTouchListener = value;
            return this;
        }

        @NotNull
        public final Builder setOverlayColor(int i) {
            this.overlayColor = i;
            return this;
        }

        @NotNull
        public final Builder setOverlayGravity(int i) {
            this.overlayGravity = i;
            return this;
        }

        @NotNull
        public final Builder setOverlayPadding(@Dp float f) {
            this.overlayPadding = TypedValue.applyDimension(1, f, Resources.getSystem().getDisplayMetrics());
            return this;
        }

        @NotNull
        public final Builder setOverlayPaddingColor(int i) {
            this.overlayPaddingColor = i;
            return this;
        }

        @NotNull
        public final Builder setOverlayPaddingShader(@NotNull Shader shader) {
            Intrinsics.checkNotNullParameter(shader, "shader");
            this.overlayPaddingShader = shader;
            return this;
        }

        @NotNull
        public final Builder setOverlayPosition(@NotNull Point value) {
            Intrinsics.checkNotNullParameter(value, "value");
            this.overlayPosition = value;
            return this;
        }

        @NotNull
        public final Builder setOverlayShape(@NotNull BalloonOverlayShape value) {
            Intrinsics.checkNotNullParameter(value, "value");
            this.overlayShape = value;
            return this;
        }

        @NotNull
        public final Builder setPreferenceName(@NotNull String value) {
            Intrinsics.checkNotNullParameter(value, "value");
            this.preferenceName = value;
            return this;
        }

        @NotNull
        public final Builder setText(@NotNull CharSequence value) {
            Intrinsics.checkNotNullParameter(value, "value");
            this.text = value;
            return this;
        }

        @NotNull
        public final Builder setTextColor(int i) {
            this.textColor = i;
            return this;
        }

        @NotNull
        public final Builder setTextForm(@NotNull TextForm value) {
            Intrinsics.checkNotNullParameter(value, "value");
            this.textForm = value;
            return this;
        }

        @NotNull
        public final Builder setTextGravity(int i) {
            this.textGravity = i;
            return this;
        }

        @NotNull
        public final Builder setTextIsHtml(boolean z) {
            this.textIsHtml = z;
            return this;
        }

        @NotNull
        public final Builder setTextLetterSpacing(@Dp float f) {
            this.textLetterSpacing = Float.valueOf(f);
            return this;
        }

        @NotNull
        public final Builder setTextLineSpacing(@Dp float f) {
            this.textLineSpacing = Float.valueOf(f);
            return this;
        }

        @NotNull
        public final Builder setTextSize(@Sp float f) {
            this.textSize = f;
            return this;
        }

        @NotNull
        public final Builder setTextTypeface(int i) {
            this.textTypeface = i;
            return this;
        }

        @NotNull
        public final Builder setWidth(@Dp int i) {
            if (i <= 0 && i != Integer.MIN_VALUE) {
                throw new IllegalArgumentException("The width of the balloon must bigger than zero.");
            }
            this.width = AbstractC4178x.a(i, 1);
            return this;
        }

        @NotNull
        public final Builder setWidthRatio(float f) {
            this.widthRatio = f;
            return this;
        }

        @NotNull
        public final Builder setBalloonHighlightAnimation(@NotNull BalloonHighlightAnimation value, long j) {
            Intrinsics.checkNotNullParameter(value, "value");
            this.balloonHighlightAnimation = value;
            this.balloonHighlightAnimationStartDelay = j;
            return this;
        }

        @NotNull
        public final Builder setLayout(@NotNull View layout) {
            Intrinsics.checkNotNullParameter(layout, "layout");
            this.layout = layout;
            return this;
        }

        public final /* synthetic */ Builder setOnBalloonClickListener(Function1 block) {
            Intrinsics.checkNotNullParameter(block, "block");
            this.onBalloonClickListener = new BalloonKt$sam$com_skydoves_balloon_OnBalloonClickListener$0(block);
            return this;
        }

        public final /* synthetic */ Builder setOnBalloonDismissListener(Function0 block) {
            Intrinsics.checkNotNullParameter(block, "block");
            this.onBalloonDismissListener = new BalloonKt$sam$com_skydoves_balloon_OnBalloonDismissListener$0(block);
            return this;
        }

        public final /* synthetic */ Builder setOnBalloonInitializedListener(Function1 block) {
            Intrinsics.checkNotNullParameter(block, "block");
            this.onBalloonInitializedListener = new BalloonKt$sam$com_skydoves_balloon_OnBalloonInitializedListener$0(block);
            return this;
        }

        public final /* synthetic */ Builder setOnBalloonOutsideTouchListener(Function2 block) {
            Intrinsics.checkNotNullParameter(block, "block");
            this.onBalloonOutsideTouchListener = new BalloonKt$sam$com_skydoves_balloon_OnBalloonOutsideTouchListener$0(block);
            setDismissWhenTouchOutside(false);
            return this;
        }

        @NotNull
        public final Builder setOnBalloonOverlayClickListener(@NotNull Function0<Unit> block) {
            Intrinsics.checkNotNullParameter(block, "block");
            this.onBalloonOverlayClickListener = new BalloonKt$sam$com_skydoves_balloon_OnBalloonOverlayClickListener$0(block);
            return this;
        }

        @NotNull
        public final Builder setTextTypeface(@NotNull Typeface value) {
            Intrinsics.checkNotNullParameter(value, "value");
            this.textTypefaceObject = value;
            return this;
        }

        @NotNull
        public final <T extends androidx.viewbinding.a> Builder setLayout(@NotNull T binding) {
            Intrinsics.checkNotNullParameter(binding, "binding");
            this.layout = binding.getRoot();
            return this;
        }

        /* renamed from: setArrowAlignAnchorPadding, reason: collision with other method in class */
        public final /* synthetic */ void m36setArrowAlignAnchorPadding(int i) {
            this.arrowAlignAnchorPadding = i;
        }

        /* renamed from: setArrowBottomPadding, reason: collision with other method in class */
        public final /* synthetic */ void m38setArrowBottomPadding(int i) {
            this.arrowBottomPadding = i;
        }

        public final /* synthetic */ void setArrowElevation(float f) {
            this.arrowElevation = f;
        }

        /* renamed from: setArrowLeftPadding, reason: collision with other method in class */
        public final /* synthetic */ void m42setArrowLeftPadding(int i) {
            this.arrowLeftPadding = i;
        }

        /* renamed from: setArrowRightPadding, reason: collision with other method in class */
        public final /* synthetic */ void m47setArrowRightPadding(int i) {
            this.arrowRightPadding = i;
        }

        /* renamed from: setArrowSize, reason: collision with other method in class */
        public final /* synthetic */ void m48setArrowSize(int i) {
            this.arrowSize = i;
        }

        /* renamed from: setArrowTopPadding, reason: collision with other method in class */
        public final /* synthetic */ void m49setArrowTopPadding(int i) {
            this.arrowTopPadding = i;
        }

        public final /* synthetic */ void setElevation(float f) {
            this.elevation = f;
        }

        /* renamed from: setIconHeight, reason: collision with other method in class */
        public final /* synthetic */ void m74setIconHeight(int i) {
            this.iconHeight = i;
        }

        /* renamed from: setIconSpace, reason: collision with other method in class */
        public final /* synthetic */ void m75setIconSpace(int i) {
            this.iconSpace = i;
        }

        /* renamed from: setIconWidth, reason: collision with other method in class */
        public final /* synthetic */ void m76setIconWidth(int i) {
            this.iconWidth = i;
        }

        /* renamed from: setMarginBottom, reason: collision with other method in class */
        public final /* synthetic */ void m81setMarginBottom(int i) {
            this.marginBottom = i;
        }

        /* renamed from: setMarginLeft, reason: collision with other method in class */
        public final /* synthetic */ void m82setMarginLeft(int i) {
            this.marginLeft = i;
        }

        /* renamed from: setMarginRight, reason: collision with other method in class */
        public final /* synthetic */ void m83setMarginRight(int i) {
            this.marginRight = i;
        }

        /* renamed from: setMarginTop, reason: collision with other method in class */
        public final /* synthetic */ void m84setMarginTop(int i) {
            this.marginTop = i;
        }

        /* renamed from: setMaxWidth, reason: collision with other method in class */
        public final /* synthetic */ void m86setMaxWidth(int i) {
            this.maxWidth = i;
        }

        /* renamed from: setMinWidth, reason: collision with other method in class */
        public final /* synthetic */ void m90setMinWidth(int i) {
            this.minWidth = i;
        }

        /* renamed from: setPaddingBottom, reason: collision with other method in class */
        public final /* synthetic */ void m107setPaddingBottom(int i) {
            this.paddingBottom = i;
        }

        /* renamed from: setPaddingLeft, reason: collision with other method in class */
        public final /* synthetic */ void m108setPaddingLeft(int i) {
            this.paddingLeft = i;
        }

        /* renamed from: setPaddingRight, reason: collision with other method in class */
        public final /* synthetic */ void m109setPaddingRight(int i) {
            this.paddingRight = i;
        }

        /* renamed from: setPaddingTop, reason: collision with other method in class */
        public final /* synthetic */ void m110setPaddingTop(int i) {
            this.paddingTop = i;
        }
    }

    @Metadata
    @InternalBalloonApi
    public static final class Companion {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private final C getScope() {
            return (C) Balloon.scope$delegate.getValue();
        }

        @NotNull
        public final kotlinx.coroutines.channels.l getChannel() {
            return (kotlinx.coroutines.channels.l) Balloon.channel$delegate.getValue();
        }

        public final void initConsumerIfNeeded() {
            if (Balloon.isConsumerActive) {
                return;
            }
            Balloon.isConsumerActive = true;
            E.A(getScope(), null, null, new Balloon$Companion$initConsumerIfNeeded$1(null), 3);
        }

        private Companion() {
        }
    }

    @Metadata
    public static abstract class Factory {
        @NotNull
        public abstract Balloon create(@NotNull Context context, J j);
    }

    @Metadata
    public /* synthetic */ class WhenMappings {
        public static final /* synthetic */ int[] $EnumSwitchMapping$0;
        public static final /* synthetic */ int[] $EnumSwitchMapping$1;
        public static final /* synthetic */ int[] $EnumSwitchMapping$2;
        public static final /* synthetic */ int[] $EnumSwitchMapping$3;
        public static final /* synthetic */ int[] $EnumSwitchMapping$4;
        public static final /* synthetic */ int[] $EnumSwitchMapping$5;
        public static final /* synthetic */ int[] $EnumSwitchMapping$6;
        public static final /* synthetic */ int[] $EnumSwitchMapping$7;

        static {
            int[] iArr = new int[ArrowOrientation.values().length];
            try {
                iArr[ArrowOrientation.BOTTOM.ordinal()] = 1;
            } catch (NoSuchFieldError unused) {
            }
            try {
                iArr[ArrowOrientation.TOP.ordinal()] = 2;
            } catch (NoSuchFieldError unused2) {
            }
            try {
                iArr[ArrowOrientation.START.ordinal()] = 3;
            } catch (NoSuchFieldError unused3) {
            }
            try {
                iArr[ArrowOrientation.END.ordinal()] = 4;
            } catch (NoSuchFieldError unused4) {
            }
            $EnumSwitchMapping$0 = iArr;
            int[] iArr2 = new int[ArrowPositionRules.values().length];
            try {
                iArr2[ArrowPositionRules.ALIGN_BALLOON.ordinal()] = 1;
            } catch (NoSuchFieldError unused5) {
            }
            try {
                iArr2[ArrowPositionRules.ALIGN_ANCHOR.ordinal()] = 2;
            } catch (NoSuchFieldError unused6) {
            }
            $EnumSwitchMapping$1 = iArr2;
            int[] iArr3 = new int[BalloonAnimation.values().length];
            try {
                iArr3[BalloonAnimation.ELASTIC.ordinal()] = 1;
            } catch (NoSuchFieldError unused7) {
            }
            try {
                iArr3[BalloonAnimation.CIRCULAR.ordinal()] = 2;
            } catch (NoSuchFieldError unused8) {
            }
            try {
                iArr3[BalloonAnimation.FADE.ordinal()] = 3;
            } catch (NoSuchFieldError unused9) {
            }
            try {
                iArr3[BalloonAnimation.OVERSHOOT.ordinal()] = 4;
            } catch (NoSuchFieldError unused10) {
            }
            try {
                iArr3[BalloonAnimation.NONE.ordinal()] = 5;
            } catch (NoSuchFieldError unused11) {
            }
            $EnumSwitchMapping$2 = iArr3;
            int[] iArr4 = new int[BalloonOverlayAnimation.values().length];
            try {
                iArr4[BalloonOverlayAnimation.FADE.ordinal()] = 1;
            } catch (NoSuchFieldError unused12) {
            }
            $EnumSwitchMapping$3 = iArr4;
            int[] iArr5 = new int[BalloonHighlightAnimation.values().length];
            try {
                iArr5[BalloonHighlightAnimation.HEARTBEAT.ordinal()] = 1;
            } catch (NoSuchFieldError unused13) {
            }
            try {
                iArr5[BalloonHighlightAnimation.SHAKE.ordinal()] = 2;
            } catch (NoSuchFieldError unused14) {
            }
            try {
                iArr5[BalloonHighlightAnimation.BREATH.ordinal()] = 3;
            } catch (NoSuchFieldError unused15) {
            }
            try {
                iArr5[BalloonHighlightAnimation.ROTATE.ordinal()] = 4;
            } catch (NoSuchFieldError unused16) {
            }
            $EnumSwitchMapping$4 = iArr5;
            int[] iArr6 = new int[PlacementType.values().length];
            try {
                iArr6[PlacementType.DROPDOWN.ordinal()] = 1;
            } catch (NoSuchFieldError unused17) {
            }
            try {
                iArr6[PlacementType.ALIGNMENT.ordinal()] = 2;
            } catch (NoSuchFieldError unused18) {
            }
            try {
                iArr6[PlacementType.CENTER.ordinal()] = 3;
            } catch (NoSuchFieldError unused19) {
            }
            $EnumSwitchMapping$5 = iArr6;
            int[] iArr7 = new int[BalloonAlign.values().length];
            try {
                iArr7[BalloonAlign.TOP.ordinal()] = 1;
            } catch (NoSuchFieldError unused20) {
            }
            try {
                iArr7[BalloonAlign.BOTTOM.ordinal()] = 2;
            } catch (NoSuchFieldError unused21) {
            }
            try {
                iArr7[BalloonAlign.START.ordinal()] = 3;
            } catch (NoSuchFieldError unused22) {
            }
            try {
                iArr7[BalloonAlign.END.ordinal()] = 4;
            } catch (NoSuchFieldError unused23) {
            }
            $EnumSwitchMapping$6 = iArr7;
            int[] iArr8 = new int[BalloonCenterAlign.values().length];
            try {
                iArr8[BalloonCenterAlign.TOP.ordinal()] = 1;
            } catch (NoSuchFieldError unused24) {
            }
            try {
                iArr8[BalloonCenterAlign.BOTTOM.ordinal()] = 2;
            } catch (NoSuchFieldError unused25) {
            }
            try {
                iArr8[BalloonCenterAlign.START.ordinal()] = 3;
            } catch (NoSuchFieldError unused26) {
            }
            try {
                iArr8[BalloonCenterAlign.END.ordinal()] = 4;
            } catch (NoSuchFieldError unused27) {
            }
            $EnumSwitchMapping$7 = iArr8;
        }
    }

    public /* synthetic */ Balloon(Context context, Builder builder, DefaultConstructorMarker defaultConstructorMarker) {
        this(context, builder);
    }

    private final Bitmap adjustArrowColorByMatchingCardBackground(ImageView imageView, float f, float f2) {
        LinearGradient linearGradient;
        int backgroundColor = this.builder.getBackgroundColor();
        PorterDuff.Mode mode = PorterDuff.Mode.SRC_IN;
        imageView.setColorFilter(backgroundColor, mode);
        Drawable drawable = imageView.getDrawable();
        Intrinsics.checkNotNullExpressionValue(drawable, "getDrawable(...)");
        Bitmap bitmapDrawableToBitmap = drawableToBitmap(drawable, imageView.getDrawable().getIntrinsicWidth(), imageView.getDrawable().getIntrinsicHeight());
        try {
            Pair<Integer, Integer> colorsFromBalloonCard = getColorsFromBalloonCard(f, f2);
            int iIntValue = ((Number) colorsFromBalloonCard.a).intValue();
            int iIntValue2 = ((Number) colorsFromBalloonCard.b).intValue();
            Bitmap bitmapCreateBitmap = Bitmap.createBitmap(bitmapDrawableToBitmap.getWidth(), bitmapDrawableToBitmap.getHeight(), Bitmap.Config.ARGB_8888);
            Intrinsics.checkNotNullExpressionValue(bitmapCreateBitmap, "createBitmap(...)");
            Canvas canvas = new Canvas(bitmapCreateBitmap);
            canvas.drawBitmap(bitmapDrawableToBitmap, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, (Paint) null);
            Paint paint = new Paint();
            int i = WhenMappings.$EnumSwitchMapping$0[this.builder.getArrowOrientation().ordinal()];
            if (i == 1) {
                linearGradient = new LinearGradient((bitmapDrawableToBitmap.getWidth() / 2) - (this.builder.getArrowSize() * 0.5f), DefinitionKt.NO_Float_VALUE, bitmapDrawableToBitmap.getWidth(), DefinitionKt.NO_Float_VALUE, iIntValue, iIntValue2, Shader.TileMode.CLAMP);
            } else {
                if (i != 2) {
                    if (i != 3) {
                        if (i != 4) {
                            throw new NoWhenBranchMatchedException();
                        }
                    }
                    linearGradient = new LinearGradient((bitmapDrawableToBitmap.getWidth() / 2) - (this.builder.getArrowSize() * 0.5f), DefinitionKt.NO_Float_VALUE, bitmapDrawableToBitmap.getWidth(), DefinitionKt.NO_Float_VALUE, iIntValue, iIntValue2, Shader.TileMode.CLAMP);
                }
                linearGradient = new LinearGradient((bitmapDrawableToBitmap.getWidth() / 2) + (this.builder.getArrowSize() * 0.5f), DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, iIntValue, iIntValue2, Shader.TileMode.CLAMP);
            }
            paint.setShader(linearGradient);
            paint.setXfermode(new PorterDuffXfermode(mode));
            canvas.drawRect(DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, bitmapDrawableToBitmap.getWidth(), bitmapDrawableToBitmap.getHeight(), paint);
            imageView.setColorFilter(0, mode);
            return bitmapCreateBitmap;
        } catch (IllegalArgumentException unused) {
            throw new IllegalArgumentException("Arrow attached outside balloon. Could not get a matching color.");
        }
    }

    private final void adjustArrowOrientationByRules(View view) {
        if (this.builder.getArrowOrientationRules() == ArrowOrientationRules.ALIGN_FIXED) {
            return;
        }
        Rect rect = new Rect();
        view.getGlobalVisibleRect(rect);
        int[] iArr = {0, 0};
        this.bodyWindow.getContentView().getLocationOnScreen(iArr);
        ArrowOrientation arrowOrientation = this.builder.getArrowOrientation();
        ArrowOrientation arrowOrientation2 = ArrowOrientation.TOP;
        if (arrowOrientation == arrowOrientation2 && iArr[1] < rect.bottom) {
            this.builder.setArrowOrientation(ArrowOrientation.BOTTOM);
        } else if (this.builder.getArrowOrientation() == ArrowOrientation.BOTTOM && iArr[1] > rect.top) {
            this.builder.setArrowOrientation(arrowOrientation2);
        }
        ArrowOrientation arrowOrientation3 = this.builder.getArrowOrientation();
        ArrowOrientation arrowOrientation4 = ArrowOrientation.START;
        if (arrowOrientation3 == arrowOrientation4 && iArr[0] < rect.right) {
            this.builder.setArrowOrientation(ArrowOrientation.END);
        } else if (this.builder.getArrowOrientation() == ArrowOrientation.END && iArr[0] > rect.left) {
            this.builder.setArrowOrientation(arrowOrientation4);
        }
        initializeBalloonContent();
    }

    private final void adjustFitsSystemWindows(ViewGroup viewGroup) {
        viewGroup.setFitsSystemWindows(false);
        IntRange intRangeH = kotlin.ranges.l.h(0, viewGroup.getChildCount());
        ArrayList<View> arrayList = new ArrayList(kotlin.collections.C.q(intRangeH, 10));
        Iterator it2 = intRangeH.iterator();
        while (it2.hasNext()) {
            arrayList.add(viewGroup.getChildAt(((P) it2).nextInt()));
        }
        for (View view : arrayList) {
            view.setFitsSystemWindows(false);
            if (view instanceof ViewGroup) {
                adjustFitsSystemWindows((ViewGroup) view);
            }
        }
    }

    private final void applyBalloonAnimation() {
        if (this.builder.getBalloonAnimationStyle() != Integer.MIN_VALUE) {
            this.bodyWindow.setAnimationStyle(this.builder.getBalloonAnimationStyle());
            return;
        }
        int i = WhenMappings.$EnumSwitchMapping$2[this.builder.getBalloonAnimation().ordinal()];
        if (i == 1) {
            this.bodyWindow.setAnimationStyle(R.style.Balloon_Elastic_Anim);
            return;
        }
        if (i == 2) {
            View contentView = this.bodyWindow.getContentView();
            Intrinsics.checkNotNullExpressionValue(contentView, "getContentView(...)");
            ViewExtensionKt.circularRevealed(contentView, this.builder.getCircularDuration());
            this.bodyWindow.setAnimationStyle(R.style.Balloon_Normal_Dispose_Anim);
            return;
        }
        if (i == 3) {
            this.bodyWindow.setAnimationStyle(R.style.Balloon_Fade_Anim);
        } else if (i == 4) {
            this.bodyWindow.setAnimationStyle(R.style.Balloon_Overshoot_Anim);
        } else {
            if (i != 5) {
                throw new NoWhenBranchMatchedException();
            }
            this.bodyWindow.setAnimationStyle(R.style.Balloon_None_Anim);
        }
    }

    private final void applyBalloonOverlayAnimation() {
        if (this.builder.getBalloonOverlayAnimationStyle() != Integer.MIN_VALUE) {
            this.overlayWindow.setAnimationStyle(this.builder.getBalloonAnimationStyle());
            return;
        }
        if (WhenMappings.$EnumSwitchMapping$3[this.builder.getBalloonOverlayAnimation().ordinal()] == 1) {
            this.overlayWindow.setAnimationStyle(R.style.Balloon_Fade_Anim);
        } else {
            this.overlayWindow.setAnimationStyle(R.style.Balloon_Normal_Anim);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final AutoDismissRunnable autoDismissRunnable_delegate$lambda$1(Balloon balloon) {
        return new AutoDismissRunnable(balloon);
    }

    public static Object awaitAlign$default(Balloon balloon, BalloonAlign balloonAlign, View view, List list, int i, int i2, h hVar, int i3, Object obj) {
        if ((i3 & 4) != 0) {
            list = K.a;
        }
        return balloon.awaitAlign(balloonAlign, view, list, (i3 & 8) != 0 ? 0 : i, (i3 & 16) != 0 ? 0 : i2, hVar);
    }

    public static /* synthetic */ Object awaitAlignBottom$default(Balloon balloon, View view, int i, int i2, h hVar, int i3, Object obj) {
        if ((i3 & 2) != 0) {
            i = 0;
        }
        if ((i3 & 4) != 0) {
            i2 = 0;
        }
        return balloon.awaitAlignBottom(view, i, i2, hVar);
    }

    public static /* synthetic */ Object awaitAlignEnd$default(Balloon balloon, View view, int i, int i2, h hVar, int i3, Object obj) {
        if ((i3 & 2) != 0) {
            i = 0;
        }
        if ((i3 & 4) != 0) {
            i2 = 0;
        }
        return balloon.awaitAlignEnd(view, i, i2, hVar);
    }

    public static /* synthetic */ Object awaitAlignStart$default(Balloon balloon, View view, int i, int i2, h hVar, int i3, Object obj) {
        if ((i3 & 2) != 0) {
            i = 0;
        }
        if ((i3 & 4) != 0) {
            i2 = 0;
        }
        return balloon.awaitAlignStart(view, i, i2, hVar);
    }

    public static /* synthetic */ Object awaitAlignTop$default(Balloon balloon, View view, int i, int i2, h hVar, int i3, Object obj) {
        if ((i3 & 2) != 0) {
            i = 0;
        }
        if ((i3 & 4) != 0) {
            i2 = 0;
        }
        return balloon.awaitAlignTop(view, i, i2, hVar);
    }

    public static /* synthetic */ Object awaitAsDropDown$default(Balloon balloon, View view, int i, int i2, h hVar, int i3, Object obj) {
        if ((i3 & 2) != 0) {
            i = 0;
        }
        if ((i3 & 4) != 0) {
            i2 = 0;
        }
        return balloon.awaitAsDropDown(view, i, i2, hVar);
    }

    public static /* synthetic */ Object awaitAtCenter$default(Balloon balloon, View view, int i, int i2, BalloonCenterAlign balloonCenterAlign, h hVar, int i3, Object obj) {
        if ((i3 & 2) != 0) {
            i = 0;
        }
        if ((i3 & 4) != 0) {
            i2 = 0;
        }
        if ((i3 & 8) != 0) {
            balloonCenterAlign = BalloonCenterAlign.TOP;
        }
        return balloon.awaitAtCenter(view, i, i2, balloonCenterAlign, hVar);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final Object awaitBalloon(BalloonPlacement balloonPlacement, h<? super Unit> hVar) {
        Companion companion = Companion;
        companion.initConsumerIfNeeded();
        Object objS = companion.getChannel().s(new DeferredBalloonGroup(A.b(new DeferredBalloon(this, balloonPlacement)), true), hVar);
        return objS == kotlin.coroutines.intrinsics.a.a ? objS : Unit.a;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final BalloonPersistence balloonPersistence_delegate$lambda$2(Balloon balloon) {
        return BalloonPersistence.Companion.getInstance(balloon.context);
    }

    private final Pair<Integer, Integer> calculateAlignOffset(BalloonPlacement balloonPlacement) {
        View anchor = balloonPlacement.getAnchor();
        int iB = kotlin.math.c.b(anchor.getMeasuredWidth() * 0.5f);
        int iB2 = kotlin.math.c.b(anchor.getMeasuredHeight() * 0.5f);
        int iB3 = kotlin.math.c.b(getMeasuredWidth() * 0.5f);
        int iB4 = kotlin.math.c.b(getMeasuredHeight() * 0.5f);
        int xOff = balloonPlacement.getXOff();
        int yOff = balloonPlacement.getYOff();
        int i = WhenMappings.$EnumSwitchMapping$6[balloonPlacement.getAlign().ordinal()];
        if (i == 1) {
            return new Pair<>(Integer.valueOf(((iB - iB3) + xOff) * this.builder.getSupportRtlLayoutFactor()), Integer.valueOf((-(anchor.getMeasuredHeight() + getMeasuredHeight())) + yOff));
        }
        if (i == 2) {
            return new Pair<>(Integer.valueOf(((iB - iB3) + xOff) * this.builder.getSupportRtlLayoutFactor()), Integer.valueOf(yOff));
        }
        if (i == 3) {
            return new Pair<>(Integer.valueOf(((-getMeasuredWidth()) + xOff) * this.builder.getSupportRtlLayoutFactor()), Integer.valueOf((-(iB4 + iB2)) + yOff));
        }
        if (i != 4) {
            throw new NoWhenBranchMatchedException();
        }
        return new Pair<>(Integer.valueOf((anchor.getMeasuredWidth() + xOff) * this.builder.getSupportRtlLayoutFactor()), Integer.valueOf((-(iB4 + iB2)) + yOff));
    }

    private final Pair<Integer, Integer> calculateCenterOffset(BalloonPlacement balloonPlacement) {
        View anchor = balloonPlacement.getAnchor();
        int iB = kotlin.math.c.b(anchor.getMeasuredWidth() * 0.5f);
        int iB2 = kotlin.math.c.b(anchor.getMeasuredHeight() * 0.5f);
        int iB3 = kotlin.math.c.b(getMeasuredWidth() * 0.5f);
        int iB4 = kotlin.math.c.b(getMeasuredHeight() * 0.5f);
        int xOff = balloonPlacement.getXOff();
        int yOff = balloonPlacement.getYOff();
        int i = WhenMappings.$EnumSwitchMapping$6[balloonPlacement.getAlign().ordinal()];
        if (i == 1) {
            return new Pair<>(Integer.valueOf(((iB - iB3) + xOff) * this.builder.getSupportRtlLayoutFactor()), Integer.valueOf((-(getMeasuredHeight() + iB2)) + yOff));
        }
        if (i == 2) {
            return new Pair<>(Integer.valueOf(((iB - iB3) + xOff) * this.builder.getSupportRtlLayoutFactor()), Integer.valueOf((-iB2) + yOff));
        }
        if (i == 3) {
            return new Pair<>(Integer.valueOf(((iB - getMeasuredWidth()) + xOff) * this.builder.getSupportRtlLayoutFactor()), Integer.valueOf(((-iB4) - iB2) + yOff));
        }
        if (i != 4) {
            throw new NoWhenBranchMatchedException();
        }
        return new Pair<>(Integer.valueOf((iB + xOff) * this.builder.getSupportRtlLayoutFactor()), Integer.valueOf(((-iB4) - iB2) + yOff));
    }

    private final Pair<Integer, Integer> calculateOffset(BalloonPlacement balloonPlacement) {
        int i = WhenMappings.$EnumSwitchMapping$5[balloonPlacement.getType().ordinal()];
        if (i == 1) {
            return new Pair<>(Integer.valueOf(balloonPlacement.getXOff()), Integer.valueOf(balloonPlacement.getYOff()));
        }
        if (i == 2) {
            return calculateAlignOffset(balloonPlacement);
        }
        if (i == 3) {
            return calculateCenterOffset(balloonPlacement);
        }
        throw new NoWhenBranchMatchedException();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final boolean canShowBalloonWindow(View view) {
        if (this.isShowing || this.destroyed) {
            return false;
        }
        Context context = this.context;
        Activity activity = context instanceof Activity ? (Activity) context : null;
        if ((activity == null || !activity.isFinishing()) && this.bodyWindow.getContentView().getParent() == null && view.isAttachedToWindow()) {
            return view.getWindowToken().isBinderAlive();
        }
        return false;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final kotlinx.coroutines.channels.l channel_delegate$lambda$56() {
        return D1.a(0, 7, null);
    }

    private final void createByBuilder() {
        androidx.lifecycle.C lifecycle;
        initializeBackground();
        initializeBalloonRoot();
        initializeBalloonWindow();
        initializeBalloonLayout();
        initializeBalloonContent();
        initializeBalloonOverlay();
        initializeBalloonListeners();
        FrameLayout root = this.binding.getRoot();
        Intrinsics.checkNotNullExpressionValue(root, "getRoot(...)");
        adjustFitsSystemWindows(root);
        if (this.builder.getLifecycleOwner() == null) {
            Object obj = this.context;
            if (obj instanceof J) {
                this.builder.setLifecycleOwner((J) obj);
                androidx.lifecycle.C lifecycle2 = ((J) this.context).getLifecycle();
                I lifecycleObserver = this.builder.getLifecycleObserver();
                if (lifecycleObserver == null) {
                    lifecycleObserver = this;
                }
                lifecycle2.a(lifecycleObserver);
                return;
            }
        }
        J lifecycleOwner = this.builder.getLifecycleOwner();
        if (lifecycleOwner == null || (lifecycle = lifecycleOwner.getLifecycle()) == null) {
            return;
        }
        I lifecycleObserver2 = this.builder.getLifecycleObserver();
        if (lifecycleObserver2 == null) {
            lifecycleObserver2 = this;
        }
        lifecycle.a(lifecycleObserver2);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final Unit dismiss$lambda$44(Balloon balloon) {
        balloon.isShowing = false;
        balloon.currentAlign = null;
        balloon.bodyWindow.dismiss();
        balloon.overlayWindow.dismiss();
        balloon.getHandler().removeCallbacks(balloon.getAutoDismissRunnable());
        return Unit.a;
    }

    private final Bitmap drawableToBitmap(Drawable drawable, int i, int i2) {
        Bitmap bitmapCreateBitmap = Bitmap.createBitmap(i, i2, Bitmap.Config.ARGB_8888);
        Intrinsics.checkNotNullExpressionValue(bitmapCreateBitmap, "createBitmap(...)");
        Canvas canvas = new Canvas(bitmapCreateBitmap);
        drawable.setBounds(0, 0, canvas.getWidth(), canvas.getHeight());
        drawable.draw(canvas);
        return bitmapCreateBitmap;
    }

    private final float getArrowConstraintPositionX(View view) {
        FrameLayout balloonContent = this.binding.balloonContent;
        Intrinsics.checkNotNullExpressionValue(balloonContent, "balloonContent");
        int i = ViewExtensionKt.getViewPointOnScreen(balloonContent).x;
        int i2 = ViewExtensionKt.getViewPointOnScreen(view).x;
        float minArrowPosition = getMinArrowPosition();
        float measuredWidth = ((getMeasuredWidth() - minArrowPosition) - this.builder.getMarginRight()) - this.builder.getMarginLeft();
        int i3 = WhenMappings.$EnumSwitchMapping$1[this.builder.getArrowPositionRules().ordinal()];
        if (i3 == 1) {
            return (this.builder.getArrowPosition() * this.binding.balloonWrapper.getWidth()) - (this.builder.getArrowSize() * 0.5f);
        }
        if (i3 != 2) {
            throw new NoWhenBranchMatchedException();
        }
        if (view.getWidth() + i2 >= i) {
            if (getMeasuredWidth() + i >= i2) {
                float f = i2;
                float f2 = i;
                float arrowPosition = (((this.builder.getArrowPosition() * view.getWidth()) + f) - f2) - (this.builder.getArrowSize() * 0.5f);
                float arrowPosition2 = (this.builder.getArrowPosition() * view.getWidth()) + f;
                if (arrowPosition2 - (this.builder.getArrowSize() * 0.5f) <= f2) {
                    return DefinitionKt.NO_Float_VALUE;
                }
                if (arrowPosition2 - (this.builder.getArrowSize() * 0.5f) > f2 && view.getWidth() <= (getMeasuredWidth() - this.builder.getMarginRight()) - this.builder.getMarginLeft()) {
                    return (arrowPosition2 - (this.builder.getArrowSize() * 0.5f)) - f2;
                }
                if (arrowPosition > getDoubleArrowSize()) {
                    if (arrowPosition <= getMeasuredWidth() - getDoubleArrowSize()) {
                        return arrowPosition;
                    }
                }
            }
            return measuredWidth;
        }
        return minArrowPosition;
    }

    private final float getArrowConstraintPositionY(View view) {
        int statusBarHeight = ViewExtensionKt.getStatusBarHeight(view, this.builder.isStatusBarVisible());
        FrameLayout balloonContent = this.binding.balloonContent;
        Intrinsics.checkNotNullExpressionValue(balloonContent, "balloonContent");
        int i = ViewExtensionKt.getViewPointOnScreen(balloonContent).y - statusBarHeight;
        int i2 = ViewExtensionKt.getViewPointOnScreen(view).y - statusBarHeight;
        float minArrowPosition = getMinArrowPosition();
        float measuredHeight = ((getMeasuredHeight() - minArrowPosition) - this.builder.getMarginTop()) - this.builder.getMarginBottom();
        int arrowSize = this.builder.getArrowSize() / 2;
        int i3 = WhenMappings.$EnumSwitchMapping$1[this.builder.getArrowPositionRules().ordinal()];
        if (i3 == 1) {
            return (this.builder.getArrowPosition() * this.binding.balloonWrapper.getHeight()) - arrowSize;
        }
        if (i3 != 2) {
            throw new NoWhenBranchMatchedException();
        }
        if (view.getHeight() + i2 >= i) {
            if (getMeasuredHeight() + i >= i2) {
                float arrowPosition = (((this.builder.getArrowPosition() * view.getHeight()) + i2) - i) - arrowSize;
                if (arrowPosition > getDoubleArrowSize()) {
                    if (arrowPosition <= getMeasuredHeight() - getDoubleArrowSize()) {
                        return arrowPosition;
                    }
                }
            }
            return measuredHeight;
        }
        return minArrowPosition;
    }

    private final BitmapDrawable getArrowForeground(ImageView imageView, float f, float f2) {
        if (this.builder.getArrowColorMatchBalloon() && GlobalExtensionKt.isAPILevelHigherThan23()) {
            return new BitmapDrawable(imageView.getResources(), adjustArrowColorByMatchingCardBackground(imageView, f, f2));
        }
        return null;
    }

    private final AutoDismissRunnable getAutoDismissRunnable() {
        return (AutoDismissRunnable) this.autoDismissRunnable$delegate.getValue();
    }

    private final Animation getBalloonHighlightAnimation() {
        int balloonHighlightAnimationStyle;
        if (this.builder.getBalloonHighlightAnimationStyle() == Integer.MIN_VALUE) {
            int i = WhenMappings.$EnumSwitchMapping$4[this.builder.getBalloonHighlightAnimation().ordinal()];
            if (i != 1) {
                if (i == 2) {
                    int i2 = WhenMappings.$EnumSwitchMapping$0[this.builder.getArrowOrientation().ordinal()];
                    if (i2 == 1) {
                        balloonHighlightAnimationStyle = R.anim.balloon_shake_top;
                    } else if (i2 == 2) {
                        balloonHighlightAnimationStyle = R.anim.balloon_shake_bottom;
                    } else if (i2 == 3) {
                        balloonHighlightAnimationStyle = R.anim.balloon_shake_right;
                    } else {
                        if (i2 != 4) {
                            throw new NoWhenBranchMatchedException();
                        }
                        balloonHighlightAnimationStyle = R.anim.balloon_shake_left;
                    }
                } else {
                    if (i != 3) {
                        if (i != 4) {
                            return null;
                        }
                        return this.builder.getBalloonRotateAnimation();
                    }
                    balloonHighlightAnimationStyle = R.anim.balloon_fade;
                }
            } else if (this.builder.isVisibleArrow()) {
                int i3 = WhenMappings.$EnumSwitchMapping$0[this.builder.getArrowOrientation().ordinal()];
                if (i3 == 1) {
                    balloonHighlightAnimationStyle = R.anim.balloon_heartbeat_top;
                } else if (i3 == 2) {
                    balloonHighlightAnimationStyle = R.anim.balloon_heartbeat_bottom;
                } else if (i3 == 3) {
                    balloonHighlightAnimationStyle = R.anim.balloon_heartbeat_right;
                } else {
                    if (i3 != 4) {
                        throw new NoWhenBranchMatchedException();
                    }
                    balloonHighlightAnimationStyle = R.anim.balloon_heartbeat_left;
                }
            } else {
                balloonHighlightAnimationStyle = R.anim.balloon_heartbeat_center;
            }
        } else {
            balloonHighlightAnimationStyle = this.builder.getBalloonHighlightAnimationStyle();
        }
        return AnimationUtils.loadAnimation(this.context, balloonHighlightAnimationStyle);
    }

    private final BalloonPersistence getBalloonPersistence() {
        return (BalloonPersistence) this.balloonPersistence$delegate.getValue();
    }

    private final Pair<Integer, Integer> getColorsFromBalloonCard(float f, float f2) {
        int pixel;
        int pixel2;
        Drawable background = this.binding.balloonCard.getBackground();
        Intrinsics.checkNotNullExpressionValue(background, "getBackground(...)");
        Bitmap bitmapDrawableToBitmap = drawableToBitmap(background, this.binding.balloonCard.getWidth() + 1, this.binding.balloonCard.getHeight() + 1);
        int i = WhenMappings.$EnumSwitchMapping$0[this.builder.getArrowOrientation().ordinal()];
        if (i == 1 || i == 2) {
            int i2 = (int) f2;
            pixel = bitmapDrawableToBitmap.getPixel((int) ((this.builder.getArrowSize() * 0.5f) + f), i2);
            pixel2 = bitmapDrawableToBitmap.getPixel((int) (f - (this.builder.getArrowSize() * 0.5f)), i2);
        } else {
            if (i != 3 && i != 4) {
                throw new NoWhenBranchMatchedException();
            }
            int i3 = (int) f;
            pixel = bitmapDrawableToBitmap.getPixel(i3, (int) ((this.builder.getArrowSize() * 0.5f) + f2));
            pixel2 = bitmapDrawableToBitmap.getPixel(i3, (int) (f2 - (this.builder.getArrowSize() * 0.5f)));
        }
        return new Pair<>(Integer.valueOf(pixel), Integer.valueOf(pixel2));
    }

    private final int getDoubleArrowSize() {
        return this.builder.getArrowSize() * 2;
    }

    private final Handler getHandler() {
        return (Handler) this.handler$delegate.getValue();
    }

    private final int getMeasuredTextWidth(int i, View view) {
        int widthRatio;
        int i2 = new Point(Resources.getSystem().getDisplayMetrics().widthPixels, Resources.getSystem().getDisplayMetrics().heightPixels).x;
        int paddingRight = view.getPaddingRight() + view.getPaddingLeft() + (this.builder.getIconDrawable() != null ? this.builder.getIconSpace() + this.builder.getIconWidth() : this.builder.getMarginLeft() + this.builder.getMarginRight() + (this.builder.getArrowSize() * 2));
        int maxWidth = this.builder.getMaxWidth() - paddingRight;
        if (maxWidth > i2) {
            maxWidth = i2;
        }
        if (this.builder.getWidthRatio() == DefinitionKt.NO_Float_VALUE) {
            if (this.builder.getMinWidthRatio() != DefinitionKt.NO_Float_VALUE || this.builder.getMaxWidthRatio() != DefinitionKt.NO_Float_VALUE) {
                int maxWidthRatio = ((int) (i2 * (this.builder.getMaxWidthRatio() == DefinitionKt.NO_Float_VALUE ? 1.0f : this.builder.getMaxWidthRatio()))) - paddingRight;
                if (i > maxWidthRatio) {
                    return maxWidthRatio;
                }
            } else if (this.builder.getWidth() != Integer.MIN_VALUE && this.builder.getWidth() <= i2) {
                widthRatio = this.builder.getWidth();
            } else if (i > maxWidth) {
                return maxWidth;
            }
            return i;
        }
        widthRatio = (int) (this.builder.getWidthRatio() * i2);
        return widthRatio - paddingRight;
    }

    private final float getMinArrowPosition() {
        return (this.builder.getArrowAlignAnchorPaddingRatio() * this.builder.getArrowSize()) + this.builder.getArrowAlignAnchorPadding();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final Handler handler_delegate$lambda$0() {
        return new Handler(Looper.getMainLooper());
    }

    private final boolean hasCustomLayout() {
        return (this.builder.getLayoutRes() == null && this.builder.getLayout() == null) ? false : true;
    }

    private final void initializeArrow(View view) {
        ImageView imageView = this.binding.balloonArrow;
        imageView.setLayoutParams(new FrameLayout.LayoutParams(this.builder.getArrowSize(), this.builder.getArrowSize()));
        imageView.setAlpha(this.builder.getAlpha());
        Drawable arrowDrawable = this.builder.getArrowDrawable();
        if (arrowDrawable != null) {
            imageView.setImageDrawable(arrowDrawable);
        }
        imageView.setPadding(this.builder.getArrowLeftPadding(), this.builder.getArrowTopPadding(), this.builder.getArrowRightPadding(), this.builder.getArrowBottomPadding());
        if (this.builder.getArrowColor() != Integer.MIN_VALUE) {
            imageView.setImageTintList(ColorStateList.valueOf(this.builder.getArrowColor()));
        } else {
            imageView.setImageTintList(ColorStateList.valueOf(this.builder.getBackgroundColor()));
        }
        imageView.setOutlineProvider(ViewOutlineProvider.BOUNDS);
        this.binding.balloonCard.post(new com.facebook.login.E(this, view, imageView, 12));
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final void initializeArrow$lambda$7$lambda$6(Balloon balloon, View view, ImageView imageView) {
        OnBalloonInitializedListener onBalloonInitializedListener = balloon.onBalloonInitializedListener;
        if (onBalloonInitializedListener != null) {
            onBalloonInitializedListener.onBalloonInitialized(balloon.getContentView());
        }
        balloon.adjustArrowOrientationByRules(view);
        balloon.updateArrow(view);
        Intrinsics.d(imageView);
        ViewExtensionKt.visible(imageView, balloon.builder.isVisibleArrow());
    }

    private final void initializeBackground() {
        RadiusLayout radiusLayout = this.binding.balloonCard;
        radiusLayout.setAlpha(this.builder.getAlpha());
        radiusLayout.setRadius(this.builder.getCornerRadius());
        float elevation = this.builder.getElevation();
        WeakHashMap weakHashMap = V.a;
        L.k(radiusLayout, elevation);
        Drawable backgroundDrawable = this.builder.getBackgroundDrawable();
        Drawable drawable = backgroundDrawable;
        if (backgroundDrawable == null) {
            GradientDrawable gradientDrawable = new GradientDrawable();
            gradientDrawable.setColor(this.builder.getBackgroundColor());
            gradientDrawable.setCornerRadius(this.builder.getCornerRadius());
            drawable = gradientDrawable;
        }
        radiusLayout.setBackground(drawable);
        radiusLayout.setPadding(this.builder.getPaddingLeft(), this.builder.getPaddingTop(), this.builder.getPaddingRight(), this.builder.getPaddingBottom());
    }

    private final void initializeBalloonContent() {
        int arrowSize = this.builder.getArrowSize() - 1;
        int elevation = (int) this.builder.getElevation();
        FrameLayout frameLayout = this.binding.balloonContent;
        int i = WhenMappings.$EnumSwitchMapping$0[this.builder.getArrowOrientation().ordinal()];
        if (i == 1) {
            if (arrowSize >= elevation) {
                elevation = arrowSize;
            }
            frameLayout.setPadding(0, arrowSize, 0, elevation);
        } else if (i == 2) {
            if (arrowSize >= elevation) {
                elevation = arrowSize;
            }
            frameLayout.setPadding(0, arrowSize, 0, elevation);
        } else if (i == 3) {
            frameLayout.setPadding(arrowSize, 0, arrowSize, 0);
        } else {
            if (i != 4) {
                throw new NoWhenBranchMatchedException();
            }
            frameLayout.setPadding(arrowSize, 0, arrowSize, 0);
        }
    }

    private final void initializeBalloonLayout() {
        if (hasCustomLayout()) {
            initializeCustomLayout();
        } else {
            initializeIcon();
            initializeText();
        }
    }

    private final void initializeBalloonListeners() {
        setOnBalloonClickListener(this.builder.getOnBalloonClickListener());
        setOnBalloonDismissListener(this.builder.getOnBalloonDismissListener());
        setOnBalloonOutsideTouchListener(this.builder.getOnBalloonOutsideTouchListener());
        setOnBalloonTouchListener(this.builder.getOnBalloonTouchListener());
        setOnBalloonOverlayClickListener(this.builder.getOnBalloonOverlayClickListener());
        setOnBalloonOverlayTouchListener(this.builder.getOnBalloonOverlayTouchListener());
    }

    private final void initializeBalloonOverlay() {
        if (this.builder.isVisibleOverlay()) {
            BalloonAnchorOverlayView balloonAnchorOverlayView = this.overlayBinding.balloonOverlayView;
            balloonAnchorOverlayView.setOverlayColor(this.builder.getOverlayColor());
            balloonAnchorOverlayView.setOverlayPadding(this.builder.getOverlayPadding());
            balloonAnchorOverlayView.setOverlayPosition(this.builder.getOverlayPosition());
            balloonAnchorOverlayView.setBalloonOverlayShape(this.builder.getOverlayShape());
            balloonAnchorOverlayView.setOverlayPaddingColor(this.builder.getOverlayPaddingColor());
            balloonAnchorOverlayView.setOverlayPaddingShader(this.builder.getOverlayPaddingShader());
            this.overlayWindow.setClippingEnabled(false);
        }
    }

    private final void initializeBalloonRoot() {
        ViewGroup.LayoutParams layoutParams = this.binding.balloonWrapper.getLayoutParams();
        Intrinsics.e(layoutParams, "null cannot be cast to non-null type android.view.ViewGroup.MarginLayoutParams");
        ((ViewGroup.MarginLayoutParams) layoutParams).setMargins(this.builder.getMarginLeft(), this.builder.getMarginTop(), this.builder.getMarginRight(), this.builder.getMarginBottom());
    }

    private final void initializeBalloonWindow() {
        PopupWindow popupWindow = this.bodyWindow;
        popupWindow.setOutsideTouchable(true);
        popupWindow.setFocusable(this.builder.isFocusable());
        popupWindow.setBackgroundDrawable(new ColorDrawable(0));
        popupWindow.setElevation(this.builder.getElevation());
        setIsAttachedInDecor(this.builder.isAttachedInDecor());
    }

    /* JADX WARN: Removed duplicated region for block: B:6:0x001d  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private final void initializeCustomLayout() {
        /*
            r4 = this;
            com.skydoves.balloon.Balloon$Builder r0 = r4.builder
            java.lang.Integer r0 = r0.getLayoutRes()
            if (r0 == 0) goto L1d
            int r0 = r0.intValue()
            android.content.Context r1 = r4.context
            android.view.LayoutInflater r1 = android.view.LayoutInflater.from(r1)
            com.skydoves.balloon.databinding.BalloonLayoutBodyBinding r2 = r4.binding
            com.skydoves.balloon.radius.RadiusLayout r2 = r2.balloonCard
            r3 = 0
            android.view.View r0 = r1.inflate(r0, r2, r3)
            if (r0 != 0) goto L25
        L1d:
            com.skydoves.balloon.Balloon$Builder r0 = r4.builder
            android.view.View r0 = r0.getLayout()
            if (r0 == 0) goto L51
        L25:
            android.view.ViewParent r1 = r0.getParent()
            boolean r2 = r1 instanceof android.view.ViewGroup
            if (r2 == 0) goto L30
            android.view.ViewGroup r1 = (android.view.ViewGroup) r1
            goto L31
        L30:
            r1 = 0
        L31:
            if (r1 == 0) goto L36
            r1.removeView(r0)
        L36:
            com.skydoves.balloon.databinding.BalloonLayoutBodyBinding r1 = r4.binding
            com.skydoves.balloon.radius.RadiusLayout r1 = r1.balloonCard
            r1.removeAllViews()
            com.skydoves.balloon.databinding.BalloonLayoutBodyBinding r1 = r4.binding
            com.skydoves.balloon.radius.RadiusLayout r1 = r1.balloonCard
            r1.addView(r0)
            com.skydoves.balloon.databinding.BalloonLayoutBodyBinding r0 = r4.binding
            com.skydoves.balloon.radius.RadiusLayout r0 = r0.balloonCard
            java.lang.String r1 = "balloonCard"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r0, r1)
            r4.traverseAndMeasureTextWidth(r0)
            return
        L51:
            java.lang.IllegalArgumentException r0 = new java.lang.IllegalArgumentException
            java.lang.String r1 = "The custom layout is null."
            r0.<init>(r1)
            throw r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.skydoves.balloon.Balloon.initializeCustomLayout():void");
    }

    private final void initializeIcon() {
        VectorTextView vectorTextView = this.binding.balloonText;
        IconForm iconForm = this.builder.getIconForm();
        if (iconForm != null) {
            Intrinsics.d(vectorTextView);
            TextViewExtensionKt.applyIconForm(vectorTextView, iconForm);
        } else {
            Intrinsics.d(vectorTextView);
            Context context = vectorTextView.getContext();
            Intrinsics.checkNotNullExpressionValue(context, "getContext(...)");
            IconForm.Builder builder = new IconForm.Builder(context);
            builder.setDrawable(this.builder.getIconDrawable());
            builder.setIconWidth(this.builder.getIconWidth());
            builder.setIconHeight(this.builder.getIconHeight());
            builder.setIconColor(this.builder.getIconColor());
            builder.setIconSpace(this.builder.getIconSpace());
            builder.setDrawableGravity(this.builder.getIconGravity());
            TextViewExtensionKt.applyIconForm(vectorTextView, builder.build());
        }
        vectorTextView.isRtlSupport(this.builder.isRtlLayout());
    }

    private final void initializeText() {
        VectorTextView vectorTextView = this.binding.balloonText;
        TextForm textForm = this.builder.getTextForm();
        if (textForm != null) {
            Intrinsics.d(vectorTextView);
            TextViewExtensionKt.applyTextForm(vectorTextView, textForm);
        } else {
            Intrinsics.d(vectorTextView);
            Context context = vectorTextView.getContext();
            Intrinsics.checkNotNullExpressionValue(context, "getContext(...)");
            TextForm.Builder builder = new TextForm.Builder(context);
            builder.setText(this.builder.getText());
            builder.setTextSize(this.builder.getTextSize());
            builder.setTextColor(this.builder.getTextColor());
            builder.setTextIsHtml(this.builder.getTextIsHtml());
            builder.setTextGravity(this.builder.getTextGravity());
            builder.setTextTypeface(this.builder.getTextTypeface());
            builder.setTextTypeface(this.builder.getTextTypefaceObject());
            builder.setTextLineSpacing(this.builder.getTextLineSpacing());
            builder.setTextLetterSpacing(this.builder.getTextLetterSpacing());
            vectorTextView.setMovementMethod(this.builder.getMovementMethod());
            builder.setEnableAutoSized(this.builder.getEnableAutoSized());
            builder.setMinAutoSizeTextSize(this.builder.getMinAutoSizeTextSize());
            builder.setMaxAutoSizeTextSize(this.builder.getMaxAutoSizeTextSize());
            TextViewExtensionKt.applyTextForm(vectorTextView, builder.build());
        }
        RadiusLayout balloonCard = this.binding.balloonCard;
        Intrinsics.checkNotNullExpressionValue(balloonCard, "balloonCard");
        measureTextWidth(vectorTextView, balloonCard);
    }

    private final void measureTextWidth(TextView textView, View view) {
        int sumOfIntrinsicWidth;
        int iMeasureText = (int) textView.getPaint().measureText(textView.getText().toString());
        Drawable[] compoundDrawablesRelative = textView.getCompoundDrawablesRelative();
        Intrinsics.checkNotNullExpressionValue(compoundDrawablesRelative, "getCompoundDrawablesRelative(...)");
        if (!DrawableExtensionKt.isExistHorizontalDrawable(compoundDrawablesRelative)) {
            Drawable[] compoundDrawables = textView.getCompoundDrawables();
            Intrinsics.checkNotNullExpressionValue(compoundDrawables, "getCompoundDrawables(...)");
            if (DrawableExtensionKt.isExistHorizontalDrawable(compoundDrawables)) {
                Drawable[] compoundDrawables2 = textView.getCompoundDrawables();
                Intrinsics.checkNotNullExpressionValue(compoundDrawables2, "getCompoundDrawables(...)");
                textView.setMinHeight(DrawableExtensionKt.getIntrinsicHeight(compoundDrawables2));
                Drawable[] compoundDrawables3 = textView.getCompoundDrawables();
                Intrinsics.checkNotNullExpressionValue(compoundDrawables3, "getCompoundDrawables(...)");
                sumOfIntrinsicWidth = DrawableExtensionKt.getSumOfIntrinsicWidth(compoundDrawables3);
            }
            textView.setMaxWidth(getMeasuredTextWidth(textView.getCompoundPaddingEnd() + textView.getCompoundPaddingStart() + iMeasureText, view));
        }
        Drawable[] compoundDrawablesRelative2 = textView.getCompoundDrawablesRelative();
        Intrinsics.checkNotNullExpressionValue(compoundDrawablesRelative2, "getCompoundDrawablesRelative(...)");
        textView.setMinHeight(DrawableExtensionKt.getIntrinsicHeight(compoundDrawablesRelative2));
        Drawable[] compoundDrawablesRelative3 = textView.getCompoundDrawablesRelative();
        Intrinsics.checkNotNullExpressionValue(compoundDrawablesRelative3, "getCompoundDrawablesRelative(...)");
        sumOfIntrinsicWidth = DrawableExtensionKt.getSumOfIntrinsicWidth(compoundDrawablesRelative3);
        iMeasureText += sumOfIntrinsicWidth;
        textView.setMaxWidth(getMeasuredTextWidth(textView.getCompoundPaddingEnd() + textView.getCompoundPaddingStart() + iMeasureText, view));
    }

    private final void passTouchEventToAnchor(View view) {
        if (this.builder.getPassTouchEventToAnchor()) {
            setOnBalloonOverlayTouchListener(new p(view, this));
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final boolean passTouchEventToAnchor$lambda$50(View view, Balloon balloon, View view2, MotionEvent event) {
        Intrinsics.checkNotNullParameter(view2, "view");
        Intrinsics.checkNotNullParameter(event, "event");
        view2.performClick();
        Rect rect = new Rect();
        view.getGlobalVisibleRect(rect);
        if (event.getAction() == 0) {
            balloon.passedEventActionDownEvent = new Pair<>(event, Boolean.valueOf(rect.contains((int) event.getRawX(), (int) event.getRawY())));
        }
        Pair<MotionEvent, Boolean> pair = balloon.passedEventActionDownEvent;
        MotionEvent motionEvent = pair != null ? (MotionEvent) pair.a : null;
        boolean zBooleanValue = pair != null ? ((Boolean) pair.b).booleanValue() : false;
        if (zBooleanValue && event.getAction() == 1) {
            View rootView = view.getRootView();
            Intrinsics.d(motionEvent);
            rootView.dispatchTouchEvent(motionEvent);
            return true;
        }
        if (!zBooleanValue) {
            return false;
        }
        view.getRootView().dispatchTouchEvent(event);
        return true;
    }

    private final Balloon relay(final Balloon balloon, final Function1<? super Balloon, Unit> function1) {
        final OnBalloonDismissListener onBalloonDismissListener = balloon.builder.getOnBalloonDismissListener();
        setOnBalloonDismissListener(new Function0<Unit>() { // from class: com.skydoves.balloon.Balloon.relay.1
            @Override // kotlin.jvm.functions.Function0
            public /* bridge */ /* synthetic */ Object invoke() {
                m122invoke();
                return Unit.a;
            }

            /* renamed from: invoke, reason: collision with other method in class */
            public final void m122invoke() {
                OnBalloonDismissListener onBalloonDismissListener2 = onBalloonDismissListener;
                if (onBalloonDismissListener2 != null) {
                    onBalloonDismissListener2.onBalloonDismiss();
                }
                if (this.destroyed) {
                    return;
                }
                function1.invoke(balloon);
            }
        });
        return balloon;
    }

    public static /* synthetic */ Balloon relayShowAlign$default(Balloon balloon, BalloonAlign balloonAlign, Balloon balloon2, View view, int i, int i2, int i3, Object obj) {
        if ((i3 & 8) != 0) {
            i = 0;
        }
        if ((i3 & 16) != 0) {
            i2 = 0;
        }
        return balloon.relayShowAlign(balloonAlign, balloon2, view, i, i2);
    }

    public static /* synthetic */ Balloon relayShowAlignBottom$default(Balloon balloon, Balloon balloon2, View view, int i, int i2, int i3, Object obj) {
        if ((i3 & 4) != 0) {
            i = 0;
        }
        if ((i3 & 8) != 0) {
            i2 = 0;
        }
        return balloon.relayShowAlignBottom(balloon2, view, i, i2);
    }

    public static /* synthetic */ Balloon relayShowAlignEnd$default(Balloon balloon, Balloon balloon2, View view, int i, int i2, int i3, Object obj) {
        if ((i3 & 4) != 0) {
            i = 0;
        }
        if ((i3 & 8) != 0) {
            i2 = 0;
        }
        return balloon.relayShowAlignEnd(balloon2, view, i, i2);
    }

    public static /* synthetic */ Balloon relayShowAlignLeft$default(Balloon balloon, Balloon balloon2, View view, int i, int i2, int i3, Object obj) {
        if ((i3 & 4) != 0) {
            i = 0;
        }
        if ((i3 & 8) != 0) {
            i2 = 0;
        }
        return balloon.relayShowAlignLeft(balloon2, view, i, i2);
    }

    public static /* synthetic */ Balloon relayShowAlignRight$default(Balloon balloon, Balloon balloon2, View view, int i, int i2, int i3, Object obj) {
        if ((i3 & 4) != 0) {
            i = 0;
        }
        if ((i3 & 8) != 0) {
            i2 = 0;
        }
        return balloon.relayShowAlignRight(balloon2, view, i, i2);
    }

    public static /* synthetic */ Balloon relayShowAlignStart$default(Balloon balloon, Balloon balloon2, View view, int i, int i2, int i3, Object obj) {
        if ((i3 & 4) != 0) {
            i = 0;
        }
        if ((i3 & 8) != 0) {
            i2 = 0;
        }
        return balloon.relayShowAlignStart(balloon2, view, i, i2);
    }

    public static /* synthetic */ Balloon relayShowAlignTop$default(Balloon balloon, Balloon balloon2, View view, int i, int i2, int i3, Object obj) {
        if ((i3 & 4) != 0) {
            i = 0;
        }
        if ((i3 & 8) != 0) {
            i2 = 0;
        }
        return balloon.relayShowAlignTop(balloon2, view, i, i2);
    }

    public static /* synthetic */ Balloon relayShowAsDropDown$default(Balloon balloon, Balloon balloon2, View view, int i, int i2, int i3, Object obj) {
        if ((i3 & 4) != 0) {
            i = 0;
        }
        if ((i3 & 8) != 0) {
            i2 = 0;
        }
        return balloon.relayShowAsDropDown(balloon2, view, i, i2);
    }

    public static /* synthetic */ Balloon relayShowAtCenter$default(Balloon balloon, Balloon balloon2, View view, int i, int i2, BalloonCenterAlign balloonCenterAlign, int i3, Object obj) {
        if ((i3 & 4) != 0) {
            i = 0;
        }
        if ((i3 & 8) != 0) {
            i2 = 0;
        }
        if ((i3 & 16) != 0) {
            balloonCenterAlign = BalloonCenterAlign.TOP;
        }
        return balloon.relayShowAtCenter(balloon2, view, i, i2, balloonCenterAlign);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final C scope_delegate$lambda$57() {
        e eVar = O.a;
        return E.c(m.a);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final void setOnBalloonClickListener$lambda$47(OnBalloonClickListener onBalloonClickListener, Balloon balloon, View view) {
        if (onBalloonClickListener != null) {
            Intrinsics.d(view);
            onBalloonClickListener.onBalloonClick(view);
        }
        if (balloon.builder.getDismissWhenClicked()) {
            balloon.dismiss();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final void setOnBalloonDismissListener$lambda$48(Balloon balloon, OnBalloonDismissListener onBalloonDismissListener) {
        balloon.stopBalloonHighlightAnimation();
        balloon.dismiss();
        if (onBalloonDismissListener != null) {
            onBalloonDismissListener.onBalloonDismiss();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final void setOnBalloonOverlayClickListener$lambda$51(OnBalloonOverlayClickListener onBalloonOverlayClickListener, Balloon balloon, View view) {
        if (onBalloonOverlayClickListener != null) {
            onBalloonOverlayClickListener.onBalloonOverlayClick();
        }
        if (balloon.builder.getDismissWhenOverlayClicked()) {
            balloon.dismiss();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final boolean setOnBalloonOverlayTouchListener$lambda$49(Function2 function2, View view, MotionEvent motionEvent) {
        return ((Boolean) function2.invoke(view, motionEvent)).booleanValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void show(BalloonPlacement balloonPlacement) {
        View anchor = balloonPlacement.getAnchor();
        if (canShowBalloonWindow(anchor)) {
            anchor.post(new com.facebook.login.E(this, anchor, balloonPlacement, 13));
        } else if (this.builder.getDismissWhenShowAgain()) {
            dismiss();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final void show$lambda$34(Balloon balloon, View view, BalloonPlacement balloonPlacement) {
        boolean zCanShowBalloonWindow = balloon.canShowBalloonWindow(view);
        Boolean boolValueOf = Boolean.valueOf(zCanShowBalloonWindow);
        if (!zCanShowBalloonWindow) {
            boolValueOf = null;
        }
        if (boolValueOf != null) {
            String preferenceName = balloon.builder.getPreferenceName();
            if (preferenceName != null) {
                if (!balloon.getBalloonPersistence().shouldShowUp(preferenceName, balloon.builder.getShowTimes())) {
                    Function0<Unit> runIfReachedShowCounts = balloon.builder.getRunIfReachedShowCounts();
                    if (runIfReachedShowCounts != null) {
                        runIfReachedShowCounts.invoke();
                        return;
                    }
                    return;
                }
                balloon.getBalloonPersistence().putIncrementedCounts(preferenceName);
            }
            balloon.isShowing = true;
            balloon.currentAlign = balloonPlacement.getAlign();
            long autoDismissDuration = balloon.builder.getAutoDismissDuration();
            if (autoDismissDuration != -1) {
                balloon.dismissWithDelay(autoDismissDuration);
            }
            if (balloon.hasCustomLayout()) {
                RadiusLayout balloonCard = balloon.binding.balloonCard;
                Intrinsics.checkNotNullExpressionValue(balloonCard, "balloonCard");
                balloon.traverseAndMeasureTextWidth(balloonCard);
            } else {
                VectorTextView balloonText = balloon.binding.balloonText;
                Intrinsics.checkNotNullExpressionValue(balloonText, "balloonText");
                RadiusLayout balloonCard2 = balloon.binding.balloonCard;
                Intrinsics.checkNotNullExpressionValue(balloonCard2, "balloonCard");
                balloon.measureTextWidth(balloonText, balloonCard2);
            }
            balloon.binding.getRoot().measure(0, 0);
            balloon.bodyWindow.setWidth(balloon.getMeasuredWidth());
            balloon.bodyWindow.setHeight(balloon.getMeasuredHeight());
            balloon.binding.balloonText.setLayoutParams(new FrameLayout.LayoutParams(-1, -1));
            balloon.initializeArrow(view);
            balloon.initializeBalloonContent();
            balloon.applyBalloonOverlayAnimation();
            balloon.showOverlayWindow(view, balloonPlacement.getSubAnchors());
            balloon.passTouchEventToAnchor(view);
            balloon.applyBalloonAnimation();
            balloon.startBalloonHighlightAnimation();
            Pair<Integer, Integer> pairCalculateOffset = balloon.calculateOffset(balloonPlacement);
            balloon.bodyWindow.showAsDropDown(view, ((Number) pairCalculateOffset.a).intValue(), ((Number) pairCalculateOffset.b).intValue());
        }
    }

    public static void showAlign$default(Balloon balloon, BalloonAlign balloonAlign, View view, List list, int i, int i2, int i3, Object obj) {
        if ((i3 & 4) != 0) {
            list = K.a;
        }
        balloon.showAlign(balloonAlign, view, list, (i3 & 8) != 0 ? 0 : i, (i3 & 16) != 0 ? 0 : i2);
    }

    public static /* synthetic */ void showAlignBottom$default(Balloon balloon, View view, int i, int i2, int i3, Object obj) {
        if ((i3 & 2) != 0) {
            i = 0;
        }
        if ((i3 & 4) != 0) {
            i2 = 0;
        }
        balloon.showAlignBottom(view, i, i2);
    }

    public static /* synthetic */ void showAlignEnd$default(Balloon balloon, View view, int i, int i2, int i3, Object obj) {
        if ((i3 & 2) != 0) {
            i = 0;
        }
        if ((i3 & 4) != 0) {
            i2 = 0;
        }
        balloon.showAlignEnd(view, i, i2);
    }

    public static /* synthetic */ void showAlignLeft$default(Balloon balloon, View view, int i, int i2, int i3, Object obj) {
        if ((i3 & 2) != 0) {
            i = 0;
        }
        if ((i3 & 4) != 0) {
            i2 = 0;
        }
        balloon.showAlignLeft(view, i, i2);
    }

    public static /* synthetic */ void showAlignRight$default(Balloon balloon, View view, int i, int i2, int i3, Object obj) {
        if ((i3 & 2) != 0) {
            i = 0;
        }
        if ((i3 & 4) != 0) {
            i2 = 0;
        }
        balloon.showAlignRight(view, i, i2);
    }

    public static /* synthetic */ void showAlignStart$default(Balloon balloon, View view, int i, int i2, int i3, Object obj) {
        if ((i3 & 2) != 0) {
            i = 0;
        }
        if ((i3 & 4) != 0) {
            i2 = 0;
        }
        balloon.showAlignStart(view, i, i2);
    }

    public static /* synthetic */ void showAlignTop$default(Balloon balloon, View view, int i, int i2, int i3, Object obj) {
        if ((i3 & 2) != 0) {
            i = 0;
        }
        if ((i3 & 4) != 0) {
            i2 = 0;
        }
        balloon.showAlignTop(view, i, i2);
    }

    public static /* synthetic */ void showAsDropDown$default(Balloon balloon, View view, int i, int i2, int i3, Object obj) {
        if ((i3 & 2) != 0) {
            i = 0;
        }
        if ((i3 & 4) != 0) {
            i2 = 0;
        }
        balloon.showAsDropDown(view, i, i2);
    }

    public static /* synthetic */ void showAtCenter$default(Balloon balloon, View view, int i, int i2, BalloonCenterAlign balloonCenterAlign, int i3, Object obj) {
        if ((i3 & 2) != 0) {
            i = 0;
        }
        if ((i3 & 4) != 0) {
            i2 = 0;
        }
        if ((i3 & 8) != 0) {
            balloonCenterAlign = BalloonCenterAlign.TOP;
        }
        balloon.showAtCenter(view, i, i2, balloonCenterAlign);
    }

    private final void showOverlayWindow(View view, List<? extends View> list) {
        if (this.builder.isVisibleOverlay()) {
            if (list.isEmpty()) {
                this.overlayBinding.balloonOverlayView.setAnchorView(view);
            } else {
                this.overlayBinding.balloonOverlayView.setAnchorViewList(CollectionsKt.d0(list, view));
            }
            this.overlayWindow.showAtLocation(view, this.builder.getOverlayGravity(), 0, 0);
        }
    }

    private final void startBalloonHighlightAnimation() {
        this.binding.balloon.post(new c(this, 0));
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final void startBalloonHighlightAnimation$lambda$28(Balloon balloon) {
        new Handler(Looper.getMainLooper()).postDelayed(new c(balloon, 1), balloon.builder.getBalloonHighlightAnimationStartDelay());
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final void startBalloonHighlightAnimation$lambda$28$lambda$27(Balloon balloon) {
        Animation balloonHighlightAnimation = balloon.getBalloonHighlightAnimation();
        if (balloonHighlightAnimation != null) {
            balloon.binding.balloon.startAnimation(balloonHighlightAnimation);
        }
    }

    private final void stopBalloonHighlightAnimation() {
        FrameLayout frameLayout = this.binding.balloon;
        Animation animation = frameLayout.getAnimation();
        if (animation != null) {
            animation.cancel();
            animation.reset();
        }
        frameLayout.clearAnimation();
    }

    private final void traverseAndMeasureTextWidth(ViewGroup viewGroup) {
        int childCount = viewGroup.getChildCount();
        for (int i = 0; i < childCount; i++) {
            View childAt = viewGroup.getChildAt(i);
            if (childAt instanceof TextView) {
                measureTextWidth((TextView) childAt, viewGroup);
            } else if (childAt instanceof ViewGroup) {
                traverseAndMeasureTextWidth((ViewGroup) childAt);
            }
        }
    }

    private final void update(BalloonPlacement balloonPlacement) {
        if (this.isShowing) {
            updateArrow(balloonPlacement.getAnchor());
            Pair<Integer, Integer> pairCalculateOffset = calculateOffset(balloonPlacement);
            this.bodyWindow.update(balloonPlacement.getAnchor(), ((Number) pairCalculateOffset.a).intValue(), ((Number) pairCalculateOffset.b).intValue(), balloonPlacement.getWidth(), balloonPlacement.getHeight());
            if (this.builder.isVisibleOverlay()) {
                this.overlayBinding.balloonOverlayView.forceInvalidate();
            }
        }
    }

    public static /* synthetic */ void update$default(Balloon balloon, View view, int i, int i2, int i3, int i4, int i5, Object obj) {
        if ((i5 & 2) != 0) {
            i = 0;
        }
        if ((i5 & 4) != 0) {
            i2 = 0;
        }
        if ((i5 & 8) != 0) {
            i3 = balloon.getMeasuredWidth();
        }
        if ((i5 & 16) != 0) {
            i4 = balloon.getMeasuredHeight();
        }
        balloon.update(view, i, i2, i3, i4);
    }

    public static /* synthetic */ void updateAlign$default(Balloon balloon, BalloonAlign balloonAlign, View view, int i, int i2, int i3, int i4, int i5, Object obj) {
        if ((i5 & 4) != 0) {
            i = 0;
        }
        if ((i5 & 8) != 0) {
            i2 = 0;
        }
        if ((i5 & 16) != 0) {
            i3 = balloon.getMeasuredWidth();
        }
        if ((i5 & 32) != 0) {
            i4 = balloon.getMeasuredHeight();
        }
        balloon.updateAlign(balloonAlign, view, i, i2, i3, i4);
    }

    public static /* synthetic */ void updateAlignBottom$default(Balloon balloon, View view, int i, int i2, int i3, int i4, int i5, Object obj) {
        if ((i5 & 2) != 0) {
            i = 0;
        }
        if ((i5 & 4) != 0) {
            i2 = 0;
        }
        if ((i5 & 8) != 0) {
            i3 = balloon.getMeasuredWidth();
        }
        if ((i5 & 16) != 0) {
            i4 = balloon.getMeasuredHeight();
        }
        balloon.updateAlignBottom(view, i, i2, i3, i4);
    }

    public static /* synthetic */ void updateAlignEnd$default(Balloon balloon, View view, int i, int i2, int i3, int i4, int i5, Object obj) {
        if ((i5 & 2) != 0) {
            i = 0;
        }
        if ((i5 & 4) != 0) {
            i2 = 0;
        }
        if ((i5 & 8) != 0) {
            i3 = balloon.getMeasuredWidth();
        }
        if ((i5 & 16) != 0) {
            i4 = balloon.getMeasuredHeight();
        }
        balloon.updateAlignEnd(view, i, i2, i3, i4);
    }

    public static /* synthetic */ void updateAlignStart$default(Balloon balloon, View view, int i, int i2, int i3, int i4, int i5, Object obj) {
        if ((i5 & 2) != 0) {
            i = 0;
        }
        if ((i5 & 4) != 0) {
            i2 = 0;
        }
        if ((i5 & 8) != 0) {
            i3 = balloon.getMeasuredWidth();
        }
        if ((i5 & 16) != 0) {
            i4 = balloon.getMeasuredHeight();
        }
        balloon.updateAlignStart(view, i, i2, i3, i4);
    }

    public static /* synthetic */ void updateAlignTop$default(Balloon balloon, View view, int i, int i2, int i3, int i4, int i5, Object obj) {
        if ((i5 & 2) != 0) {
            i = 0;
        }
        if ((i5 & 4) != 0) {
            i2 = 0;
        }
        if ((i5 & 8) != 0) {
            i3 = balloon.getMeasuredWidth();
        }
        if ((i5 & 16) != 0) {
            i4 = balloon.getMeasuredHeight();
        }
        balloon.updateAlignTop(view, i, i2, i3, i4);
    }

    private final void updateArrow(View view) {
        ImageView imageView = this.binding.balloonArrow;
        int i = WhenMappings.$EnumSwitchMapping$0[ArrowOrientation.Companion.getRTLSupportOrientation$balloon_release(this.builder.getArrowOrientation(), this.builder.isRtlLayout()).ordinal()];
        if (i == 1) {
            imageView.setRotation(180.0f);
            imageView.setX(getArrowConstraintPositionX(view));
            imageView.setY((this.binding.balloonCard.getY() + this.binding.balloonCard.getHeight()) - 1);
            float arrowElevation = this.builder.getArrowElevation();
            WeakHashMap weakHashMap = V.a;
            L.k(imageView, arrowElevation);
            imageView.setForeground(getArrowForeground(imageView, imageView.getX(), this.binding.balloonCard.getHeight()));
            return;
        }
        if (i == 2) {
            imageView.setRotation(DefinitionKt.NO_Float_VALUE);
            imageView.setX(getArrowConstraintPositionX(view));
            imageView.setY((this.binding.balloonCard.getY() - this.builder.getArrowSize()) + 1);
            imageView.setForeground(getArrowForeground(imageView, imageView.getX(), DefinitionKt.NO_Float_VALUE));
            return;
        }
        if (i == 3) {
            imageView.setRotation(-90.0f);
            imageView.setX((this.binding.balloonCard.getX() - this.builder.getArrowSize()) + 1);
            imageView.setY(getArrowConstraintPositionY(view));
            imageView.setForeground(getArrowForeground(imageView, DefinitionKt.NO_Float_VALUE, imageView.getY()));
            return;
        }
        if (i != 4) {
            throw new NoWhenBranchMatchedException();
        }
        imageView.setRotation(90.0f);
        imageView.setX((this.binding.balloonCard.getX() + this.binding.balloonCard.getWidth()) - 1);
        imageView.setY(getArrowConstraintPositionY(view));
        imageView.setForeground(getArrowForeground(imageView, this.binding.balloonCard.getWidth(), imageView.getY()));
    }

    public final Object awaitAlign(@NotNull BalloonAlign balloonAlign, @NotNull View view, @NotNull List<? extends View> list, int i, int i2, @NotNull h<? super Unit> hVar) {
        Object objAwaitBalloon = awaitBalloon(new BalloonPlacement(view, list, balloonAlign, i, i2, null, 0, 0, 224, null), hVar);
        return objAwaitBalloon == kotlin.coroutines.intrinsics.a.a ? objAwaitBalloon : Unit.a;
    }

    public final Object awaitAlignBottom(@NotNull View view, int i, int i2, @NotNull h<? super Unit> hVar) {
        Object objAwaitBalloon = awaitBalloon(new BalloonPlacement(view, null, BalloonAlign.BOTTOM, i, i2, null, 0, 0, 226, null), hVar);
        return objAwaitBalloon == kotlin.coroutines.intrinsics.a.a ? objAwaitBalloon : Unit.a;
    }

    public final Object awaitAlignEnd(@NotNull View view, int i, int i2, @NotNull h<? super Unit> hVar) {
        Object objAwaitBalloon = awaitBalloon(new BalloonPlacement(view, null, BalloonAlign.END, i, i2, null, 0, 0, 226, null), hVar);
        return objAwaitBalloon == kotlin.coroutines.intrinsics.a.a ? objAwaitBalloon : Unit.a;
    }

    public final Object awaitAlignStart(@NotNull View view, int i, int i2, @NotNull h<? super Unit> hVar) {
        Object objAwaitBalloon = awaitBalloon(new BalloonPlacement(view, null, BalloonAlign.START, i, i2, null, 0, 0, 226, null), hVar);
        return objAwaitBalloon == kotlin.coroutines.intrinsics.a.a ? objAwaitBalloon : Unit.a;
    }

    public final Object awaitAlignTop(@NotNull View view, int i, int i2, @NotNull h<? super Unit> hVar) {
        Object objAwaitBalloon = awaitBalloon(new BalloonPlacement(view, null, BalloonAlign.TOP, i, i2, null, 0, 0, 226, null), hVar);
        return objAwaitBalloon == kotlin.coroutines.intrinsics.a.a ? objAwaitBalloon : Unit.a;
    }

    public final Object awaitAsDropDown(@NotNull View view, int i, int i2, @NotNull h<? super Unit> hVar) {
        Object objAwaitBalloon = awaitBalloon(new BalloonPlacement(view, null, null, i, i2, PlacementType.DROPDOWN, 0, 0, 198, null), hVar);
        return objAwaitBalloon == kotlin.coroutines.intrinsics.a.a ? objAwaitBalloon : Unit.a;
    }

    public final Object awaitAtCenter(@NotNull View view, int i, int i2, @NotNull BalloonCenterAlign balloonCenterAlign, @NotNull h<? super Unit> hVar) {
        Object objAwaitBalloon = awaitBalloon(new BalloonPlacement(view, null, balloonCenterAlign.toAlign(), i, i2, PlacementType.CENTER, 0, 0, 194, null), hVar);
        return objAwaitBalloon == kotlin.coroutines.intrinsics.a.a ? objAwaitBalloon : Unit.a;
    }

    public final void clearAllPreferences() {
        getBalloonPersistence().clearAllPreferences();
    }

    public final void dismiss() {
        if (this.isShowing) {
            final a aVar = new a(this, 0);
            if (this.builder.getBalloonAnimation() != BalloonAnimation.CIRCULAR) {
                aVar.invoke();
                return;
            }
            final View contentView = this.bodyWindow.getContentView();
            Intrinsics.checkNotNullExpressionValue(contentView, "getContentView(...)");
            final long circularDuration = this.builder.getCircularDuration();
            contentView.post(new Runnable() { // from class: com.skydoves.balloon.Balloon$dismiss$$inlined$circularUnRevealed$1
                @Override // java.lang.Runnable
                public final void run() {
                    if (contentView.isAttachedToWindow()) {
                        View view = contentView;
                        Animator animatorCreateCircularReveal = ViewAnimationUtils.createCircularReveal(view, (contentView.getRight() + view.getLeft()) / 2, (contentView.getBottom() + contentView.getTop()) / 2, Math.max(contentView.getWidth(), contentView.getHeight()), DefinitionKt.NO_Float_VALUE);
                        animatorCreateCircularReveal.setDuration(circularDuration);
                        animatorCreateCircularReveal.start();
                        final Function0 function0 = aVar;
                        animatorCreateCircularReveal.addListener(new AnimatorListenerAdapter() { // from class: com.skydoves.balloon.Balloon$dismiss$$inlined$circularUnRevealed$1.1
                            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                            public void onAnimationEnd(Animator animation) {
                                Intrinsics.checkNotNullParameter(animation, "animation");
                                super.onAnimationEnd(animation);
                                function0.invoke();
                            }
                        });
                    }
                }
            });
        }
    }

    public final boolean dismissWithDelay(long j) {
        return getHandler().postDelayed(getAutoDismissRunnable(), j);
    }

    @NotNull
    public final View getBalloonArrowView() {
        ImageView balloonArrow = this.binding.balloonArrow;
        Intrinsics.checkNotNullExpressionValue(balloonArrow, "balloonArrow");
        return balloonArrow;
    }

    @NotNull
    public final PopupWindow getBodyWindow() {
        return this.bodyWindow;
    }

    @NotNull
    public final ViewGroup getContentView() {
        RadiusLayout balloonCard = this.binding.balloonCard;
        Intrinsics.checkNotNullExpressionValue(balloonCard, "balloonCard");
        return balloonCard;
    }

    public final BalloonAlign getCurrentAlign() {
        return this.currentAlign;
    }

    public final int getMeasuredHeight() {
        return this.builder.getHeight() != Integer.MIN_VALUE ? this.builder.getHeight() : this.binding.getRoot().getMeasuredHeight();
    }

    public final int getMeasuredWidth() {
        int i = new Point(Resources.getSystem().getDisplayMetrics().widthPixels, Resources.getSystem().getDisplayMetrics().heightPixels).x;
        if (this.builder.getWidthRatio() != DefinitionKt.NO_Float_VALUE) {
            return (int) (this.builder.getWidthRatio() * i);
        }
        if (this.builder.getMinWidthRatio() != DefinitionKt.NO_Float_VALUE || this.builder.getMaxWidthRatio() != DefinitionKt.NO_Float_VALUE) {
            float f = i;
            return kotlin.ranges.l.c(this.binding.getRoot().getMeasuredWidth(), (int) (this.builder.getMinWidthRatio() * f), (int) (f * (this.builder.getMaxWidthRatio() == DefinitionKt.NO_Float_VALUE ? 1.0f : this.builder.getMaxWidthRatio())));
        }
        if (this.builder.getWidth() != Integer.MIN_VALUE) {
            int width = this.builder.getWidth();
            if (width <= i) {
                return width;
            }
        } else {
            int iC = kotlin.ranges.l.c(this.binding.getRoot().getMeasuredWidth(), this.builder.getMinWidth(), this.builder.getMaxWidth());
            if (iC <= i) {
                return iC;
            }
        }
        return i;
    }

    @NotNull
    public final PopupWindow getOverlayWindow() {
        return this.overlayWindow;
    }

    public final boolean isShowing() {
        return this.isShowing;
    }

    @Override // androidx.lifecycle.InterfaceC1250k
    public /* bridge */ /* synthetic */ void onCreate(@NotNull J j) {
        super.onCreate(j);
    }

    @Override // androidx.lifecycle.InterfaceC1250k
    public void onDestroy(@NotNull J owner) {
        androidx.lifecycle.C lifecycle;
        Intrinsics.checkNotNullParameter(owner, "owner");
        super.onDestroy(owner);
        this.destroyed = true;
        this.overlayWindow.dismiss();
        this.bodyWindow.dismiss();
        J lifecycleOwner = this.builder.getLifecycleOwner();
        if (lifecycleOwner == null || (lifecycle = lifecycleOwner.getLifecycle()) == null) {
            return;
        }
        lifecycle.b(this);
    }

    @Override // androidx.lifecycle.InterfaceC1250k
    public void onPause(@NotNull J owner) {
        Intrinsics.checkNotNullParameter(owner, "owner");
        super.onPause(owner);
        if (this.builder.getDismissWhenLifecycleOnPause()) {
            dismiss();
        }
    }

    @Override // androidx.lifecycle.InterfaceC1250k
    public /* bridge */ /* synthetic */ void onResume(@NotNull J j) {
        super.onResume(j);
    }

    @Override // androidx.lifecycle.InterfaceC1250k
    public /* bridge */ /* synthetic */ void onStart(@NotNull J j) {
        super.onStart(j);
    }

    @Override // androidx.lifecycle.InterfaceC1250k
    public /* bridge */ /* synthetic */ void onStop(@NotNull J j) {
        super.onStop(j);
    }

    @NotNull
    public final Balloon relayShowAlign(@NotNull BalloonAlign align, @NotNull Balloon balloon, @NotNull View anchor) {
        Intrinsics.checkNotNullParameter(align, "align");
        Intrinsics.checkNotNullParameter(balloon, "balloon");
        Intrinsics.checkNotNullParameter(anchor, "anchor");
        return relayShowAlign$default(this, align, balloon, anchor, 0, 0, 24, null);
    }

    @NotNull
    public final Balloon relayShowAlignBottom(@NotNull Balloon balloon, @NotNull View anchor) {
        Intrinsics.checkNotNullParameter(balloon, "balloon");
        Intrinsics.checkNotNullParameter(anchor, "anchor");
        return relayShowAlignBottom$default(this, balloon, anchor, 0, 0, 12, null);
    }

    @NotNull
    public final Balloon relayShowAlignEnd(@NotNull Balloon balloon, @NotNull View anchor) {
        Intrinsics.checkNotNullParameter(balloon, "balloon");
        Intrinsics.checkNotNullParameter(anchor, "anchor");
        return relayShowAlignEnd$default(this, balloon, anchor, 0, 0, 12, null);
    }

    @InterfaceC4935d
    @NotNull
    public final Balloon relayShowAlignLeft(@NotNull Balloon balloon, @NotNull View anchor) {
        Intrinsics.checkNotNullParameter(balloon, "balloon");
        Intrinsics.checkNotNullParameter(anchor, "anchor");
        return relayShowAlignLeft$default(this, balloon, anchor, 0, 0, 12, null);
    }

    @InterfaceC4935d
    @NotNull
    public final Balloon relayShowAlignRight(@NotNull Balloon balloon, @NotNull View anchor) {
        Intrinsics.checkNotNullParameter(balloon, "balloon");
        Intrinsics.checkNotNullParameter(anchor, "anchor");
        return relayShowAlignRight$default(this, balloon, anchor, 0, 0, 12, null);
    }

    @NotNull
    public final Balloon relayShowAlignStart(@NotNull Balloon balloon, @NotNull View anchor) {
        Intrinsics.checkNotNullParameter(balloon, "balloon");
        Intrinsics.checkNotNullParameter(anchor, "anchor");
        return relayShowAlignStart$default(this, balloon, anchor, 0, 0, 12, null);
    }

    @NotNull
    public final Balloon relayShowAlignTop(@NotNull Balloon balloon, @NotNull View anchor) {
        Intrinsics.checkNotNullParameter(balloon, "balloon");
        Intrinsics.checkNotNullParameter(anchor, "anchor");
        return relayShowAlignTop$default(this, balloon, anchor, 0, 0, 12, null);
    }

    @NotNull
    public final Balloon relayShowAsDropDown(@NotNull Balloon balloon, @NotNull View anchor) {
        Intrinsics.checkNotNullParameter(balloon, "balloon");
        Intrinsics.checkNotNullParameter(anchor, "anchor");
        return relayShowAsDropDown$default(this, balloon, anchor, 0, 0, 12, null);
    }

    @NotNull
    public final Balloon relayShowAtCenter(@NotNull Balloon balloon, @NotNull View anchor) {
        Intrinsics.checkNotNullParameter(balloon, "balloon");
        Intrinsics.checkNotNullParameter(anchor, "anchor");
        return relayShowAtCenter$default(this, balloon, anchor, 0, 0, null, 28, null);
    }

    @NotNull
    public final Balloon setIsAttachedInDecor(boolean z) {
        this.bodyWindow.setAttachedInDecor(z);
        return this;
    }

    public final void setOnBalloonClickListener(OnBalloonClickListener onBalloonClickListener) {
        if (onBalloonClickListener != null || this.builder.getDismissWhenClicked()) {
            this.binding.balloonWrapper.setOnClickListener(new com.quizlet.upgrade.ui.fragment.e(3, onBalloonClickListener, this));
        }
    }

    public final void setOnBalloonDismissListener(final OnBalloonDismissListener onBalloonDismissListener) {
        this.bodyWindow.setOnDismissListener(new PopupWindow.OnDismissListener() { // from class: com.skydoves.balloon.b
            @Override // android.widget.PopupWindow.OnDismissListener
            public final void onDismiss() {
                Balloon.setOnBalloonDismissListener$lambda$48(this.a, onBalloonDismissListener);
            }
        });
    }

    public final void setOnBalloonInitializedListener(OnBalloonInitializedListener onBalloonInitializedListener) {
        this.onBalloonInitializedListener = onBalloonInitializedListener;
    }

    public final void setOnBalloonOutsideTouchListener(final OnBalloonOutsideTouchListener onBalloonOutsideTouchListener) {
        this.bodyWindow.setTouchInterceptor(new View.OnTouchListener() { // from class: com.skydoves.balloon.Balloon.setOnBalloonOutsideTouchListener.1
            @Override // android.view.View.OnTouchListener
            @SuppressLint({"ClickableViewAccessibility"})
            public boolean onTouch(View view, MotionEvent event) {
                Intrinsics.checkNotNullParameter(view, "view");
                Intrinsics.checkNotNullParameter(event, "event");
                if (event.getAction() == 4) {
                    if (Balloon.this.builder.getDismissWhenTouchOutside()) {
                        Balloon.this.dismiss();
                    }
                    OnBalloonOutsideTouchListener onBalloonOutsideTouchListener2 = onBalloonOutsideTouchListener;
                    if (onBalloonOutsideTouchListener2 != null) {
                        onBalloonOutsideTouchListener2.onBalloonOutsideTouch(view, event);
                    }
                    return true;
                }
                if (!Balloon.this.builder.getDismissWhenTouchMargin() || event.getAction() != 1) {
                    return false;
                }
                FrameLayout balloonWrapper = Balloon.this.binding.balloonWrapper;
                Intrinsics.checkNotNullExpressionValue(balloonWrapper, "balloonWrapper");
                if (ViewExtensionKt.getViewPointOnScreen(balloonWrapper).x <= event.getRawX()) {
                    FrameLayout balloonWrapper2 = Balloon.this.binding.balloonWrapper;
                    Intrinsics.checkNotNullExpressionValue(balloonWrapper2, "balloonWrapper");
                    if (Balloon.this.binding.balloonWrapper.getMeasuredWidth() + ViewExtensionKt.getViewPointOnScreen(balloonWrapper2).x >= event.getRawX()) {
                        return false;
                    }
                }
                if (Balloon.this.builder.getDismissWhenTouchOutside()) {
                    Balloon.this.dismiss();
                }
                OnBalloonOutsideTouchListener onBalloonOutsideTouchListener3 = onBalloonOutsideTouchListener;
                if (onBalloonOutsideTouchListener3 != null) {
                    onBalloonOutsideTouchListener3.onBalloonOutsideTouch(view, event);
                }
                return true;
            }
        });
    }

    public final void setOnBalloonOverlayClickListener(OnBalloonOverlayClickListener onBalloonOverlayClickListener) {
        this.overlayBinding.getRoot().setOnClickListener(new com.quizlet.upgrade.ui.fragment.e(4, onBalloonOverlayClickListener, this));
    }

    public final void setOnBalloonOverlayTouchListener(View.OnTouchListener onTouchListener) {
        if (onTouchListener != null) {
            this.overlayWindow.setTouchInterceptor(onTouchListener);
        }
    }

    public final void setOnBalloonTouchListener(View.OnTouchListener onTouchListener) {
        if (onTouchListener != null) {
            this.bodyWindow.setTouchInterceptor(onTouchListener);
        }
    }

    public final boolean shouldShowUp() {
        String preferenceName = this.builder.getPreferenceName();
        if (preferenceName != null) {
            return getBalloonPersistence().shouldShowUp(preferenceName, this.builder.getShowTimes());
        }
        return true;
    }

    public final void showAlign(@NotNull BalloonAlign align, @NotNull View mainAnchor) {
        Intrinsics.checkNotNullParameter(align, "align");
        Intrinsics.checkNotNullParameter(mainAnchor, "mainAnchor");
        showAlign$default(this, align, mainAnchor, null, 0, 0, 28, null);
    }

    public final void showAlignBottom(@NotNull View anchor) {
        Intrinsics.checkNotNullParameter(anchor, "anchor");
        showAlignBottom$default(this, anchor, 0, 0, 6, null);
    }

    public final void showAlignEnd(@NotNull View anchor) {
        Intrinsics.checkNotNullParameter(anchor, "anchor");
        showAlignEnd$default(this, anchor, 0, 0, 6, null);
    }

    @InterfaceC4935d
    public final void showAlignLeft(@NotNull View anchor) {
        Intrinsics.checkNotNullParameter(anchor, "anchor");
        showAlignLeft$default(this, anchor, 0, 0, 6, null);
    }

    @InterfaceC4935d
    public final void showAlignRight(@NotNull View anchor) {
        Intrinsics.checkNotNullParameter(anchor, "anchor");
        showAlignRight$default(this, anchor, 0, 0, 6, null);
    }

    public final void showAlignStart(@NotNull View anchor) {
        Intrinsics.checkNotNullParameter(anchor, "anchor");
        showAlignStart$default(this, anchor, 0, 0, 6, null);
    }

    public final void showAlignTop(@NotNull View anchor) {
        Intrinsics.checkNotNullParameter(anchor, "anchor");
        showAlignTop$default(this, anchor, 0, 0, 6, null);
    }

    public final void showAsDropDown(@NotNull View anchor) {
        Intrinsics.checkNotNullParameter(anchor, "anchor");
        showAsDropDown$default(this, anchor, 0, 0, 6, null);
    }

    public final void showAtCenter(@NotNull View anchor) {
        Intrinsics.checkNotNullParameter(anchor, "anchor");
        showAtCenter$default(this, anchor, 0, 0, null, 14, null);
    }

    public final void updateAlign(@NotNull BalloonAlign align, @NotNull View anchor) {
        Intrinsics.checkNotNullParameter(align, "align");
        Intrinsics.checkNotNullParameter(anchor, "anchor");
        updateAlign$default(this, align, anchor, 0, 0, 0, 0, 60, null);
    }

    public final void updateAlignBottom(@NotNull View anchor) {
        Intrinsics.checkNotNullParameter(anchor, "anchor");
        updateAlignBottom$default(this, anchor, 0, 0, 0, 0, 30, null);
    }

    public final void updateAlignEnd(@NotNull View anchor) {
        Intrinsics.checkNotNullParameter(anchor, "anchor");
        updateAlignEnd$default(this, anchor, 0, 0, 0, 0, 30, null);
    }

    public final void updateAlignStart(@NotNull View anchor) {
        Intrinsics.checkNotNullParameter(anchor, "anchor");
        updateAlignStart$default(this, anchor, 0, 0, 0, 0, 30, null);
    }

    public final void updateAlignTop(@NotNull View anchor) {
        Intrinsics.checkNotNullParameter(anchor, "anchor");
        updateAlignTop$default(this, anchor, 0, 0, 0, 0, 30, null);
    }

    @InternalBalloonApi
    public final void updateSizeOfBalloonCard(int i, int i2) {
        this.builder.setMeasuredWidth(i);
        if (this.binding.balloonCard.getChildCount() != 0) {
            RadiusLayout balloonCard = this.binding.balloonCard;
            Intrinsics.checkNotNullExpressionValue(balloonCard, "balloonCard");
            View childAt = balloonCard.getChildAt(0);
            if (childAt == null) {
                throw new IndexOutOfBoundsException("Index: 0, Size: " + balloonCard.getChildCount());
            }
            ViewGroup.LayoutParams layoutParams = childAt.getLayoutParams();
            if (layoutParams == null) {
                throw new NullPointerException("null cannot be cast to non-null type android.view.ViewGroup.LayoutParams");
            }
            layoutParams.width = i;
            layoutParams.height = i2;
            childAt.setLayoutParams(layoutParams);
        }
    }

    private Balloon(Context context, Builder builder) {
        this.context = context;
        this.builder = builder;
        BalloonLayoutBodyBinding balloonLayoutBodyBindingInflate = BalloonLayoutBodyBinding.inflate(LayoutInflater.from(context), null, false);
        Intrinsics.checkNotNullExpressionValue(balloonLayoutBodyBindingInflate, "inflate(...)");
        this.binding = balloonLayoutBodyBindingInflate;
        BalloonLayoutOverlayBinding balloonLayoutOverlayBindingInflate = BalloonLayoutOverlayBinding.inflate(LayoutInflater.from(context), null, false);
        Intrinsics.checkNotNullExpressionValue(balloonLayoutOverlayBindingInflate, "inflate(...)");
        this.overlayBinding = balloonLayoutOverlayBindingInflate;
        this.bodyWindow = new PopupWindow(balloonLayoutBodyBindingInflate.getRoot(), -2, -2);
        this.overlayWindow = new PopupWindow(balloonLayoutOverlayBindingInflate.getRoot(), -1, -1);
        this.onBalloonInitializedListener = builder.getOnBalloonInitializedListener();
        kotlin.m mVar = kotlin.m.c;
        this.handler$delegate = l.a(mVar, new com.quizlet.quizletandroid.ui.startpage.nav2.composables.b(25));
        this.autoDismissRunnable$delegate = l.a(mVar, new a(this, 1));
        this.balloonPersistence$delegate = l.a(mVar, new a(this, 2));
        createByBuilder();
    }

    @NotNull
    public final Balloon relayShowAlign(@NotNull BalloonAlign align, @NotNull Balloon balloon, @NotNull View anchor, int i) {
        Intrinsics.checkNotNullParameter(align, "align");
        Intrinsics.checkNotNullParameter(balloon, "balloon");
        Intrinsics.checkNotNullParameter(anchor, "anchor");
        return relayShowAlign$default(this, align, balloon, anchor, i, 0, 16, null);
    }

    @NotNull
    public final Balloon relayShowAlignBottom(@NotNull Balloon balloon, @NotNull View anchor, int i) {
        Intrinsics.checkNotNullParameter(balloon, "balloon");
        Intrinsics.checkNotNullParameter(anchor, "anchor");
        return relayShowAlignBottom$default(this, balloon, anchor, i, 0, 8, null);
    }

    @NotNull
    public final Balloon relayShowAlignEnd(@NotNull Balloon balloon, @NotNull View anchor, int i) {
        Intrinsics.checkNotNullParameter(balloon, "balloon");
        Intrinsics.checkNotNullParameter(anchor, "anchor");
        return relayShowAlignEnd$default(this, balloon, anchor, i, 0, 8, null);
    }

    @InterfaceC4935d
    @NotNull
    public final Balloon relayShowAlignLeft(@NotNull Balloon balloon, @NotNull View anchor, int i) {
        Intrinsics.checkNotNullParameter(balloon, "balloon");
        Intrinsics.checkNotNullParameter(anchor, "anchor");
        return relayShowAlignLeft$default(this, balloon, anchor, i, 0, 8, null);
    }

    @InterfaceC4935d
    @NotNull
    public final Balloon relayShowAlignRight(@NotNull Balloon balloon, @NotNull View anchor, int i) {
        Intrinsics.checkNotNullParameter(balloon, "balloon");
        Intrinsics.checkNotNullParameter(anchor, "anchor");
        return relayShowAlignRight$default(this, balloon, anchor, i, 0, 8, null);
    }

    @NotNull
    public final Balloon relayShowAlignStart(@NotNull Balloon balloon, @NotNull View anchor, int i) {
        Intrinsics.checkNotNullParameter(balloon, "balloon");
        Intrinsics.checkNotNullParameter(anchor, "anchor");
        return relayShowAlignStart$default(this, balloon, anchor, i, 0, 8, null);
    }

    @NotNull
    public final Balloon relayShowAlignTop(@NotNull Balloon balloon, @NotNull View anchor, int i) {
        Intrinsics.checkNotNullParameter(balloon, "balloon");
        Intrinsics.checkNotNullParameter(anchor, "anchor");
        return relayShowAlignTop$default(this, balloon, anchor, i, 0, 8, null);
    }

    @NotNull
    public final Balloon relayShowAsDropDown(@NotNull Balloon balloon, @NotNull View anchor, int i) {
        Intrinsics.checkNotNullParameter(balloon, "balloon");
        Intrinsics.checkNotNullParameter(anchor, "anchor");
        return relayShowAsDropDown$default(this, balloon, anchor, i, 0, 8, null);
    }

    @NotNull
    public final Balloon relayShowAtCenter(@NotNull Balloon balloon, @NotNull View anchor, int i) {
        Intrinsics.checkNotNullParameter(balloon, "balloon");
        Intrinsics.checkNotNullParameter(anchor, "anchor");
        return relayShowAtCenter$default(this, balloon, anchor, i, 0, null, 24, null);
    }

    public final /* synthetic */ void setOnBalloonDismissListener(Function0 block) {
        Intrinsics.checkNotNullParameter(block, "block");
        setOnBalloonDismissListener(new BalloonKt$sam$com_skydoves_balloon_OnBalloonDismissListener$0(block));
    }

    public final /* synthetic */ void setOnBalloonInitializedListener(Function1 block) {
        Intrinsics.checkNotNullParameter(block, "block");
        setOnBalloonInitializedListener(new BalloonKt$sam$com_skydoves_balloon_OnBalloonInitializedListener$0(block));
    }

    public final /* synthetic */ void setOnBalloonOverlayClickListener(Function0 block) {
        Intrinsics.checkNotNullParameter(block, "block");
        setOnBalloonOverlayClickListener(new BalloonKt$sam$com_skydoves_balloon_OnBalloonOverlayClickListener$0(block));
    }

    public final void setOnBalloonOverlayTouchListener(@NotNull Function2<? super View, ? super MotionEvent, Boolean> block) {
        Intrinsics.checkNotNullParameter(block, "block");
        setOnBalloonOverlayTouchListener(new d(block, 6));
    }

    public final void showAlign(@NotNull BalloonAlign align, @NotNull View mainAnchor, @NotNull List<? extends View> subAnchorList) {
        Intrinsics.checkNotNullParameter(align, "align");
        Intrinsics.checkNotNullParameter(mainAnchor, "mainAnchor");
        Intrinsics.checkNotNullParameter(subAnchorList, "subAnchorList");
        showAlign$default(this, align, mainAnchor, subAnchorList, 0, 0, 24, null);
    }

    public final void showAlignBottom(@NotNull View anchor, int i) {
        Intrinsics.checkNotNullParameter(anchor, "anchor");
        showAlignBottom$default(this, anchor, i, 0, 4, null);
    }

    public final void showAlignEnd(@NotNull View anchor, int i) {
        Intrinsics.checkNotNullParameter(anchor, "anchor");
        showAlignEnd$default(this, anchor, i, 0, 4, null);
    }

    @InterfaceC4935d
    public final void showAlignLeft(@NotNull View anchor, int i) {
        Intrinsics.checkNotNullParameter(anchor, "anchor");
        showAlignLeft$default(this, anchor, i, 0, 4, null);
    }

    @InterfaceC4935d
    public final void showAlignRight(@NotNull View anchor, int i) {
        Intrinsics.checkNotNullParameter(anchor, "anchor");
        showAlignRight$default(this, anchor, i, 0, 4, null);
    }

    public final void showAlignStart(@NotNull View anchor, int i) {
        Intrinsics.checkNotNullParameter(anchor, "anchor");
        showAlignStart$default(this, anchor, i, 0, 4, null);
    }

    public final void showAlignTop(@NotNull View anchor, int i) {
        Intrinsics.checkNotNullParameter(anchor, "anchor");
        showAlignTop$default(this, anchor, i, 0, 4, null);
    }

    public final void showAsDropDown(@NotNull View anchor, int i) {
        Intrinsics.checkNotNullParameter(anchor, "anchor");
        showAsDropDown$default(this, anchor, i, 0, 4, null);
    }

    public final void showAtCenter(@NotNull View anchor, int i) {
        Intrinsics.checkNotNullParameter(anchor, "anchor");
        showAtCenter$default(this, anchor, i, 0, null, 12, null);
    }

    public final void updateAlign(@NotNull BalloonAlign align, @NotNull View anchor, int i) {
        Intrinsics.checkNotNullParameter(align, "align");
        Intrinsics.checkNotNullParameter(anchor, "anchor");
        updateAlign$default(this, align, anchor, i, 0, 0, 0, 56, null);
    }

    public final void updateAlignBottom(@NotNull View anchor, int i) {
        Intrinsics.checkNotNullParameter(anchor, "anchor");
        updateAlignBottom$default(this, anchor, i, 0, 0, 0, 28, null);
    }

    public final void updateAlignEnd(@NotNull View anchor, int i) {
        Intrinsics.checkNotNullParameter(anchor, "anchor");
        updateAlignEnd$default(this, anchor, i, 0, 0, 0, 28, null);
    }

    public final void updateAlignStart(@NotNull View anchor, int i) {
        Intrinsics.checkNotNullParameter(anchor, "anchor");
        updateAlignStart$default(this, anchor, i, 0, 0, 0, 28, null);
    }

    public final void updateAlignTop(@NotNull View anchor, int i) {
        Intrinsics.checkNotNullParameter(anchor, "anchor");
        updateAlignTop$default(this, anchor, i, 0, 0, 0, 28, null);
    }

    @NotNull
    public final Balloon relayShowAlign(@NotNull final BalloonAlign align, @NotNull final Balloon balloon, @NotNull final View anchor, final int i, final int i2) {
        Intrinsics.checkNotNullParameter(align, "align");
        Intrinsics.checkNotNullParameter(balloon, "balloon");
        Intrinsics.checkNotNullParameter(anchor, "anchor");
        final OnBalloonDismissListener onBalloonDismissListener = balloon.builder.getOnBalloonDismissListener();
        setOnBalloonDismissListener(new Function0<Unit>() { // from class: com.skydoves.balloon.Balloon$relayShowAlign$$inlined$relay$1
            @Override // kotlin.jvm.functions.Function0
            public /* bridge */ /* synthetic */ Object invoke() {
                m26invoke();
                return Unit.a;
            }

            /* renamed from: invoke, reason: collision with other method in class */
            public final void m26invoke() {
                OnBalloonDismissListener onBalloonDismissListener2 = onBalloonDismissListener;
                if (onBalloonDismissListener2 != null) {
                    onBalloonDismissListener2.onBalloonDismiss();
                }
                if (this.destroyed) {
                    return;
                }
                Balloon balloon2 = balloon;
                int i3 = Balloon.WhenMappings.$EnumSwitchMapping$6[align.ordinal()];
                if (i3 == 1) {
                    balloon2.showAlignTop(anchor, i, i2);
                    return;
                }
                if (i3 == 2) {
                    balloon2.showAlignBottom(anchor, i, i2);
                } else if (i3 == 3) {
                    balloon2.showAlignStart(anchor, i, i2);
                } else {
                    if (i3 != 4) {
                        throw new NoWhenBranchMatchedException();
                    }
                    balloon2.showAlignEnd(anchor, i, i2);
                }
            }
        });
        return balloon;
    }

    @NotNull
    public final Balloon relayShowAlignBottom(@NotNull final Balloon balloon, @NotNull final View anchor, final int i, final int i2) {
        Intrinsics.checkNotNullParameter(balloon, "balloon");
        Intrinsics.checkNotNullParameter(anchor, "anchor");
        final OnBalloonDismissListener onBalloonDismissListener = balloon.builder.getOnBalloonDismissListener();
        setOnBalloonDismissListener(new Function0<Unit>() { // from class: com.skydoves.balloon.Balloon$relayShowAlignBottom$$inlined$relay$1
            @Override // kotlin.jvm.functions.Function0
            public /* bridge */ /* synthetic */ Object invoke() {
                m27invoke();
                return Unit.a;
            }

            /* renamed from: invoke, reason: collision with other method in class */
            public final void m27invoke() {
                OnBalloonDismissListener onBalloonDismissListener2 = onBalloonDismissListener;
                if (onBalloonDismissListener2 != null) {
                    onBalloonDismissListener2.onBalloonDismiss();
                }
                if (this.destroyed) {
                    return;
                }
                balloon.showAlignBottom(anchor, i, i2);
            }
        });
        return balloon;
    }

    @NotNull
    public final Balloon relayShowAlignEnd(@NotNull final Balloon balloon, @NotNull final View anchor, final int i, final int i2) {
        Intrinsics.checkNotNullParameter(balloon, "balloon");
        Intrinsics.checkNotNullParameter(anchor, "anchor");
        final OnBalloonDismissListener onBalloonDismissListener = balloon.builder.getOnBalloonDismissListener();
        setOnBalloonDismissListener(new Function0<Unit>() { // from class: com.skydoves.balloon.Balloon$relayShowAlignEnd$$inlined$relay$1
            @Override // kotlin.jvm.functions.Function0
            public /* bridge */ /* synthetic */ Object invoke() {
                m28invoke();
                return Unit.a;
            }

            /* renamed from: invoke, reason: collision with other method in class */
            public final void m28invoke() {
                OnBalloonDismissListener onBalloonDismissListener2 = onBalloonDismissListener;
                if (onBalloonDismissListener2 != null) {
                    onBalloonDismissListener2.onBalloonDismiss();
                }
                if (this.destroyed) {
                    return;
                }
                balloon.showAlignEnd(anchor, i, i2);
            }
        });
        return balloon;
    }

    @InterfaceC4935d
    @NotNull
    public final Balloon relayShowAlignLeft(@NotNull final Balloon balloon, @NotNull final View anchor, final int i, final int i2) {
        Intrinsics.checkNotNullParameter(balloon, "balloon");
        Intrinsics.checkNotNullParameter(anchor, "anchor");
        final OnBalloonDismissListener onBalloonDismissListener = balloon.builder.getOnBalloonDismissListener();
        setOnBalloonDismissListener(new Function0<Unit>() { // from class: com.skydoves.balloon.Balloon$relayShowAlignLeft$$inlined$relay$1
            @Override // kotlin.jvm.functions.Function0
            public /* bridge */ /* synthetic */ Object invoke() {
                m29invoke();
                return Unit.a;
            }

            /* renamed from: invoke, reason: collision with other method in class */
            public final void m29invoke() {
                OnBalloonDismissListener onBalloonDismissListener2 = onBalloonDismissListener;
                if (onBalloonDismissListener2 != null) {
                    onBalloonDismissListener2.onBalloonDismiss();
                }
                if (this.destroyed) {
                    return;
                }
                balloon.showAlignLeft(anchor, i, i2);
            }
        });
        return balloon;
    }

    @InterfaceC4935d
    @NotNull
    public final Balloon relayShowAlignRight(@NotNull final Balloon balloon, @NotNull final View anchor, final int i, final int i2) {
        Intrinsics.checkNotNullParameter(balloon, "balloon");
        Intrinsics.checkNotNullParameter(anchor, "anchor");
        final OnBalloonDismissListener onBalloonDismissListener = balloon.builder.getOnBalloonDismissListener();
        setOnBalloonDismissListener(new Function0<Unit>() { // from class: com.skydoves.balloon.Balloon$relayShowAlignRight$$inlined$relay$1
            @Override // kotlin.jvm.functions.Function0
            public /* bridge */ /* synthetic */ Object invoke() {
                m30invoke();
                return Unit.a;
            }

            /* renamed from: invoke, reason: collision with other method in class */
            public final void m30invoke() {
                OnBalloonDismissListener onBalloonDismissListener2 = onBalloonDismissListener;
                if (onBalloonDismissListener2 != null) {
                    onBalloonDismissListener2.onBalloonDismiss();
                }
                if (this.destroyed) {
                    return;
                }
                balloon.showAlignRight(anchor, i, i2);
            }
        });
        return balloon;
    }

    @NotNull
    public final Balloon relayShowAlignStart(@NotNull final Balloon balloon, @NotNull final View anchor, final int i, final int i2) {
        Intrinsics.checkNotNullParameter(balloon, "balloon");
        Intrinsics.checkNotNullParameter(anchor, "anchor");
        final OnBalloonDismissListener onBalloonDismissListener = balloon.builder.getOnBalloonDismissListener();
        setOnBalloonDismissListener(new Function0<Unit>() { // from class: com.skydoves.balloon.Balloon$relayShowAlignStart$$inlined$relay$1
            @Override // kotlin.jvm.functions.Function0
            public /* bridge */ /* synthetic */ Object invoke() {
                m31invoke();
                return Unit.a;
            }

            /* renamed from: invoke, reason: collision with other method in class */
            public final void m31invoke() {
                OnBalloonDismissListener onBalloonDismissListener2 = onBalloonDismissListener;
                if (onBalloonDismissListener2 != null) {
                    onBalloonDismissListener2.onBalloonDismiss();
                }
                if (this.destroyed) {
                    return;
                }
                balloon.showAlignStart(anchor, i, i2);
            }
        });
        return balloon;
    }

    @NotNull
    public final Balloon relayShowAlignTop(@NotNull final Balloon balloon, @NotNull final View anchor, final int i, final int i2) {
        Intrinsics.checkNotNullParameter(balloon, "balloon");
        Intrinsics.checkNotNullParameter(anchor, "anchor");
        final OnBalloonDismissListener onBalloonDismissListener = balloon.builder.getOnBalloonDismissListener();
        setOnBalloonDismissListener(new Function0<Unit>() { // from class: com.skydoves.balloon.Balloon$relayShowAlignTop$$inlined$relay$1
            @Override // kotlin.jvm.functions.Function0
            public /* bridge */ /* synthetic */ Object invoke() {
                m32invoke();
                return Unit.a;
            }

            /* renamed from: invoke, reason: collision with other method in class */
            public final void m32invoke() {
                OnBalloonDismissListener onBalloonDismissListener2 = onBalloonDismissListener;
                if (onBalloonDismissListener2 != null) {
                    onBalloonDismissListener2.onBalloonDismiss();
                }
                if (this.destroyed) {
                    return;
                }
                balloon.showAlignTop(anchor, i, i2);
            }
        });
        return balloon;
    }

    @NotNull
    public final Balloon relayShowAsDropDown(@NotNull final Balloon balloon, @NotNull final View anchor, final int i, final int i2) {
        Intrinsics.checkNotNullParameter(balloon, "balloon");
        Intrinsics.checkNotNullParameter(anchor, "anchor");
        final OnBalloonDismissListener onBalloonDismissListener = balloon.builder.getOnBalloonDismissListener();
        setOnBalloonDismissListener(new Function0<Unit>() { // from class: com.skydoves.balloon.Balloon$relayShowAsDropDown$$inlined$relay$1
            @Override // kotlin.jvm.functions.Function0
            public /* bridge */ /* synthetic */ Object invoke() {
                m33invoke();
                return Unit.a;
            }

            /* renamed from: invoke, reason: collision with other method in class */
            public final void m33invoke() {
                OnBalloonDismissListener onBalloonDismissListener2 = onBalloonDismissListener;
                if (onBalloonDismissListener2 != null) {
                    onBalloonDismissListener2.onBalloonDismiss();
                }
                if (this.destroyed) {
                    return;
                }
                balloon.showAsDropDown(anchor, i, i2);
            }
        });
        return balloon;
    }

    @NotNull
    public final Balloon relayShowAtCenter(@NotNull Balloon balloon, @NotNull View anchor, int i, int i2) {
        Intrinsics.checkNotNullParameter(balloon, "balloon");
        Intrinsics.checkNotNullParameter(anchor, "anchor");
        return relayShowAtCenter$default(this, balloon, anchor, i, i2, null, 16, null);
    }

    public final /* synthetic */ void setOnBalloonClickListener(Function1 block) {
        Intrinsics.checkNotNullParameter(block, "block");
        setOnBalloonClickListener(new BalloonKt$sam$com_skydoves_balloon_OnBalloonClickListener$0(block));
    }

    public final void showAlign(@NotNull BalloonAlign align, @NotNull View mainAnchor, @NotNull List<? extends View> subAnchorList, int i) {
        Intrinsics.checkNotNullParameter(align, "align");
        Intrinsics.checkNotNullParameter(mainAnchor, "mainAnchor");
        Intrinsics.checkNotNullParameter(subAnchorList, "subAnchorList");
        showAlign$default(this, align, mainAnchor, subAnchorList, i, 0, 16, null);
    }

    public final void showAlignBottom(@NotNull View anchor, int i, int i2) {
        Intrinsics.checkNotNullParameter(anchor, "anchor");
        show(new BalloonPlacement(anchor, null, BalloonAlign.BOTTOM, i, i2, null, 0, 0, 226, null));
    }

    public final void showAlignEnd(@NotNull View anchor, int i, int i2) {
        Intrinsics.checkNotNullParameter(anchor, "anchor");
        show(new BalloonPlacement(anchor, null, BalloonAlign.END, i, i2, null, 0, 0, 226, null));
    }

    @InterfaceC4935d
    public final void showAlignLeft(@NotNull View anchor, int i, int i2) {
        Intrinsics.checkNotNullParameter(anchor, "anchor");
        show(new BalloonPlacement(anchor, null, BalloonAlign.START, i, i2, null, 0, 0, 226, null));
    }

    @InterfaceC4935d
    public final void showAlignRight(@NotNull View anchor, int i, int i2) {
        Intrinsics.checkNotNullParameter(anchor, "anchor");
        show(new BalloonPlacement(anchor, null, BalloonAlign.END, i, i2, null, 0, 0, 226, null));
    }

    public final void showAlignStart(@NotNull View anchor, int i, int i2) {
        Intrinsics.checkNotNullParameter(anchor, "anchor");
        show(new BalloonPlacement(anchor, null, BalloonAlign.START, i, i2, null, 0, 0, 226, null));
    }

    public final void showAlignTop(@NotNull View anchor, int i, int i2) {
        Intrinsics.checkNotNullParameter(anchor, "anchor");
        show(new BalloonPlacement(anchor, null, BalloonAlign.TOP, i, i2, null, 0, 0, 226, null));
    }

    public final void showAsDropDown(@NotNull View anchor, int i, int i2) {
        Intrinsics.checkNotNullParameter(anchor, "anchor");
        show(new BalloonPlacement(anchor, null, null, i, i2, PlacementType.DROPDOWN, 0, 0, 198, null));
    }

    public final void showAtCenter(@NotNull View anchor, int i, int i2) {
        Intrinsics.checkNotNullParameter(anchor, "anchor");
        showAtCenter$default(this, anchor, i, i2, null, 8, null);
    }

    public final void updateAlign(@NotNull BalloonAlign align, @NotNull View anchor, int i, int i2) {
        Intrinsics.checkNotNullParameter(align, "align");
        Intrinsics.checkNotNullParameter(anchor, "anchor");
        updateAlign$default(this, align, anchor, i, i2, 0, 0, 48, null);
    }

    public final void updateAlignBottom(@NotNull View anchor, int i, int i2) {
        Intrinsics.checkNotNullParameter(anchor, "anchor");
        updateAlignBottom$default(this, anchor, i, i2, 0, 0, 24, null);
    }

    public final void updateAlignEnd(@NotNull View anchor, int i, int i2) {
        Intrinsics.checkNotNullParameter(anchor, "anchor");
        updateAlignEnd$default(this, anchor, i, i2, 0, 0, 24, null);
    }

    public final void updateAlignStart(@NotNull View anchor, int i, int i2) {
        Intrinsics.checkNotNullParameter(anchor, "anchor");
        updateAlignStart$default(this, anchor, i, i2, 0, 0, 24, null);
    }

    public final void updateAlignTop(@NotNull View anchor, int i, int i2) {
        Intrinsics.checkNotNullParameter(anchor, "anchor");
        updateAlignTop$default(this, anchor, i, i2, 0, 0, 24, null);
    }

    @NotNull
    public final Balloon relayShowAtCenter(@NotNull final Balloon balloon, @NotNull final View anchor, final int i, final int i2, @NotNull final BalloonCenterAlign centerAlign) {
        Intrinsics.checkNotNullParameter(balloon, "balloon");
        Intrinsics.checkNotNullParameter(anchor, "anchor");
        Intrinsics.checkNotNullParameter(centerAlign, "centerAlign");
        final OnBalloonDismissListener onBalloonDismissListener = balloon.builder.getOnBalloonDismissListener();
        setOnBalloonDismissListener(new Function0<Unit>() { // from class: com.skydoves.balloon.Balloon$relayShowAtCenter$$inlined$relay$1
            @Override // kotlin.jvm.functions.Function0
            public /* bridge */ /* synthetic */ Object invoke() {
                m34invoke();
                return Unit.a;
            }

            /* renamed from: invoke, reason: collision with other method in class */
            public final void m34invoke() {
                OnBalloonDismissListener onBalloonDismissListener2 = onBalloonDismissListener;
                if (onBalloonDismissListener2 != null) {
                    onBalloonDismissListener2.onBalloonDismiss();
                }
                if (this.destroyed) {
                    return;
                }
                balloon.showAtCenter(anchor, i, i2, centerAlign);
            }
        });
        return balloon;
    }

    public final /* synthetic */ void setOnBalloonOutsideTouchListener(Function2 block) {
        Intrinsics.checkNotNullParameter(block, "block");
        setOnBalloonOutsideTouchListener(new BalloonKt$sam$com_skydoves_balloon_OnBalloonOutsideTouchListener$0(block));
    }

    public final void showAlign(@NotNull BalloonAlign align, @NotNull View mainAnchor, @NotNull List<? extends View> subAnchorList, int i, int i2) {
        Intrinsics.checkNotNullParameter(align, "align");
        Intrinsics.checkNotNullParameter(mainAnchor, "mainAnchor");
        Intrinsics.checkNotNullParameter(subAnchorList, "subAnchorList");
        show(new BalloonPlacement(mainAnchor, subAnchorList, align, i, i2, null, 0, 0, 224, null));
    }

    public final void showAtCenter(@NotNull View anchor, int i, int i2, @NotNull BalloonCenterAlign centerAlign) {
        BalloonAlign balloonAlign;
        Intrinsics.checkNotNullParameter(anchor, "anchor");
        Intrinsics.checkNotNullParameter(centerAlign, "centerAlign");
        PlacementType placementType = PlacementType.CENTER;
        int i3 = WhenMappings.$EnumSwitchMapping$7[centerAlign.ordinal()];
        if (i3 == 1) {
            balloonAlign = BalloonAlign.TOP;
        } else if (i3 == 2) {
            balloonAlign = BalloonAlign.BOTTOM;
        } else if (i3 == 3) {
            balloonAlign = BalloonAlign.START;
        } else if (i3 == 4) {
            balloonAlign = BalloonAlign.END;
        } else {
            throw new NoWhenBranchMatchedException();
        }
        show(new BalloonPlacement(anchor, null, balloonAlign, i, i2, placementType, 0, 0, 194, null));
    }

    public final void updateAlign(@NotNull BalloonAlign align, @NotNull View anchor, int i, int i2, int i3) {
        Intrinsics.checkNotNullParameter(align, "align");
        Intrinsics.checkNotNullParameter(anchor, "anchor");
        updateAlign$default(this, align, anchor, i, i2, i3, 0, 32, null);
    }

    public final void updateAlignBottom(@NotNull View anchor, int i, int i2, int i3) {
        Intrinsics.checkNotNullParameter(anchor, "anchor");
        updateAlignBottom$default(this, anchor, i, i2, i3, 0, 16, null);
    }

    public final void updateAlignEnd(@NotNull View anchor, int i, int i2, int i3) {
        Intrinsics.checkNotNullParameter(anchor, "anchor");
        updateAlignEnd$default(this, anchor, i, i2, i3, 0, 16, null);
    }

    public final void updateAlignStart(@NotNull View anchor, int i, int i2, int i3) {
        Intrinsics.checkNotNullParameter(anchor, "anchor");
        updateAlignStart$default(this, anchor, i, i2, i3, 0, 16, null);
    }

    public final void updateAlignTop(@NotNull View anchor, int i, int i2, int i3) {
        Intrinsics.checkNotNullParameter(anchor, "anchor");
        updateAlignTop$default(this, anchor, i, i2, i3, 0, 16, null);
    }

    public final void updateAlign(@NotNull BalloonAlign align, @NotNull View anchor, int i, int i2, int i3, int i4) {
        Intrinsics.checkNotNullParameter(align, "align");
        Intrinsics.checkNotNullParameter(anchor, "anchor");
        update(new BalloonPlacement(anchor, null, align, i, i2, null, i3, i4, 34, null));
    }

    public final void updateAlignBottom(@NotNull View anchor, int i, int i2, int i3, int i4) {
        Intrinsics.checkNotNullParameter(anchor, "anchor");
        update(new BalloonPlacement(anchor, null, BalloonAlign.BOTTOM, i, i2, null, i3, i4, 34, null));
    }

    public final void updateAlignEnd(@NotNull View anchor, int i, int i2, int i3, int i4) {
        Intrinsics.checkNotNullParameter(anchor, "anchor");
        update(new BalloonPlacement(anchor, null, BalloonAlign.END, i, i2, null, i3, i4, 34, null));
    }

    public final void updateAlignStart(@NotNull View anchor, int i, int i2, int i3, int i4) {
        Intrinsics.checkNotNullParameter(anchor, "anchor");
        update(new BalloonPlacement(anchor, null, BalloonAlign.START, i, i2, null, i3, i4, 34, null));
    }

    public final void updateAlignTop(@NotNull View anchor, int i, int i2, int i3, int i4) {
        Intrinsics.checkNotNullParameter(anchor, "anchor");
        update(new BalloonPlacement(anchor, null, BalloonAlign.TOP, i, i2, null, i3, i4, 34, null));
    }

    public final void update(@NotNull View anchor, int i, int i2, int i3, int i4) {
        Intrinsics.checkNotNullParameter(anchor, "anchor");
        update(new BalloonPlacement(anchor, null, null, i, i2, PlacementType.CENTER, i3, i4, 6, null));
    }
}

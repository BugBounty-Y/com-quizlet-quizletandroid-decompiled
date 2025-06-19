package com.braze.ui.support;

import android.app.Activity;
import android.content.Context;
import android.os.Build;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewParent;
import androidx.arch.core.executor.d;
import androidx.core.view.C1054k;
import androidx.core.view.D0;
import com.amazon.device.ads.DtbConstants;
import com.braze.enums.inappmessage.Orientation;
import com.braze.support.BrazeLogger;
import com.braze.support.p;
import com.braze.triggers.managers.h;
import com.braze.ui.inappmessage.listeners.a;
import kotlin.Metadata;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes.dex */
public abstract class ViewUtils {

    @NotNull
    private static final String TAG = BrazeLogger.INSTANCE.getBrazeLogTag("ViewUtils");

    public static final double convertDpToPixels(@NotNull Context context, double d) {
        Intrinsics.checkNotNullParameter(context, "context");
        return d * context.getResources().getDisplayMetrics().density;
    }

    public static final int getMaxSafeBottomInset(@NotNull D0 windowInsets) {
        Intrinsics.checkNotNullParameter(windowInsets, "windowInsets");
        C1054k c1054kF = windowInsets.a.f();
        int i = 0;
        if (c1054kF != null && Build.VERSION.SDK_INT >= 28) {
            i = d.i(c1054kF.a);
        }
        return Math.max(i, windowInsets.a.g(519).d);
    }

    public static final int getMaxSafeLeftInset(@NotNull D0 windowInsets) {
        Intrinsics.checkNotNullParameter(windowInsets, "windowInsets");
        C1054k c1054kF = windowInsets.a.f();
        int iJ = 0;
        if (c1054kF != null && Build.VERSION.SDK_INT >= 28) {
            iJ = d.j(c1054kF.a);
        }
        return Math.max(iJ, windowInsets.a.g(519).a);
    }

    public static final int getMaxSafeRightInset(@NotNull D0 windowInsets) {
        Intrinsics.checkNotNullParameter(windowInsets, "windowInsets");
        C1054k c1054kF = windowInsets.a.f();
        int iK = 0;
        if (c1054kF != null && Build.VERSION.SDK_INT >= 28) {
            iK = d.k(c1054kF.a);
        }
        return Math.max(iK, windowInsets.a.g(519).c);
    }

    public static final int getMaxSafeTopInset(@NotNull D0 windowInsets) {
        Intrinsics.checkNotNullParameter(windowInsets, "windowInsets");
        C1054k c1054kF = windowInsets.a.f();
        int iL = 0;
        if (c1054kF != null && Build.VERSION.SDK_INT >= 28) {
            iL = d.l(c1054kF.a);
        }
        return Math.max(iL, windowInsets.a.g(519).b);
    }

    public static final int getStatusBarHeight(@NotNull Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        int identifier = context.getResources().getIdentifier("status_bar_height", "dimen", DtbConstants.NATIVE_OS_NAME);
        if (identifier > 0) {
            return context.getResources().getDimensionPixelSize(identifier);
        }
        return 0;
    }

    public static final boolean isCurrentOrientationValid(int i, @NotNull Orientation preferredOrientation) {
        Intrinsics.checkNotNullParameter(preferredOrientation, "preferredOrientation");
        if (i == 2 && preferredOrientation == Orientation.LANDSCAPE) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, TAG, BrazeLogger.Priority.D, (Throwable) null, false, (Function0) new a(22), 12, (Object) null);
            return true;
        }
        if (i == 1 && preferredOrientation == Orientation.PORTRAIT) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, TAG, BrazeLogger.Priority.D, (Throwable) null, false, (Function0) new a(23), 12, (Object) null);
            return true;
        }
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, TAG, BrazeLogger.Priority.D, (Throwable) null, false, (Function0) new p(i, preferredOrientation, 3), 12, (Object) null);
        return false;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String isCurrentOrientationValid$lambda$5() {
        return "Current and preferred orientation are landscape.";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String isCurrentOrientationValid$lambda$6() {
        return "Current and preferred orientation are portrait.";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String isCurrentOrientationValid$lambda$7(int i, Orientation orientation) {
        return "Current orientation " + i + " and preferred orientation " + orientation + " don't match";
    }

    public static final boolean isDeviceInNightMode(@NotNull Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        return (context.getResources().getConfiguration().uiMode & 48) == 32;
    }

    public static final boolean isDeviceNotInTouchMode(@NotNull View view) {
        Intrinsics.checkNotNullParameter(view, "view");
        return !view.isInTouchMode();
    }

    public static final boolean isRunningOnTablet(@NotNull Activity activity) {
        Intrinsics.checkNotNullParameter(activity, "<this>");
        return activity.getResources().getConfiguration().smallestScreenWidthDp >= 600;
    }

    public static final void removeViewFromParent(View view) {
        if (view == null) {
            try {
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, TAG, BrazeLogger.Priority.D, (Throwable) null, false, (Function0) new a(20), 12, (Object) null);
            } catch (Exception e) {
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, TAG, BrazeLogger.Priority.E, (Throwable) e, false, (Function0) new a(21), 8, (Object) null);
                return;
            }
        }
        if ((view != null ? view.getParent() : null) instanceof ViewGroup) {
            ViewParent parent = view.getParent();
            Intrinsics.e(parent, "null cannot be cast to non-null type android.view.ViewGroup");
            ViewGroup viewGroup = (ViewGroup) parent;
            viewGroup.removeView(view);
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, TAG, BrazeLogger.Priority.D, (Throwable) null, false, (Function0) new h(7, view, viewGroup), 12, (Object) null);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String removeViewFromParent$lambda$0() {
        return "View passed in is null. Not removing from parent.";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String removeViewFromParent$lambda$1(View view, ViewGroup viewGroup) {
        return "Removed view: " + view + "\nfrom parent: " + viewGroup;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String removeViewFromParent$lambda$2() {
        return "Caught exception while removing view from parent.";
    }

    public static final void setActivityRequestedOrientation(@NotNull Activity activity, int i) {
        Intrinsics.checkNotNullParameter(activity, "<this>");
        try {
            activity.setRequestedOrientation(i);
        } catch (Exception e) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, TAG, BrazeLogger.Priority.E, (Throwable) e, false, (Function0) new p(i, activity, 2), 8, (Object) null);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String setActivityRequestedOrientation$lambda$4(int i, Activity activity) {
        StringBuilder sbV = android.support.v4.media.session.a.v(i, "Failed to set requested orientation ", " for activity class: ");
        sbV.append(activity.getLocalClassName());
        return sbV.toString();
    }

    public static final void setFocusableInTouchModeAndRequestFocus(@NotNull View view) {
        Intrinsics.checkNotNullParameter(view, "<this>");
        try {
            view.setFocusableInTouchMode(true);
            view.requestFocus();
        } catch (Exception e) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, TAG, BrazeLogger.Priority.E, (Throwable) e, false, (Function0) new a(19), 8, (Object) null);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String setFocusableInTouchModeAndRequestFocus$lambda$3() {
        return "Caught exception while setting view to focusable in touch mode and requesting focus.";
    }

    public static final void setHeightOnViewLayoutParams(@NotNull View view, int i) {
        Intrinsics.checkNotNullParameter(view, "view");
        ViewGroup.LayoutParams layoutParams = view.getLayoutParams();
        layoutParams.height = i;
        view.setLayoutParams(layoutParams);
    }
}

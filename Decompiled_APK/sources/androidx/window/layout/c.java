package androidx.window.layout;

import android.app.Activity;
import android.content.res.Configuration;
import android.content.res.Resources;
import android.graphics.Point;
import android.graphics.Rect;
import android.util.Log;
import android.view.Display;
import android.view.DisplayCutout;
import androidx.webkit.internal.f;
import com.amazon.device.ads.DtbConstants;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import kotlin.collections.B;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class c implements b {
    public static final c b = new c();
    public static final String c;

    static {
        String simpleName = c.class.getSimpleName();
        Intrinsics.checkNotNullExpressionValue(simpleName, "WindowMetricsCalculatorC…at::class.java.simpleName");
        c = simpleName;
        B.f(1, 2, 4, 8, 16, 32, 64, 128);
    }

    public static Rect a(Activity activity) throws IllegalAccessException, NoSuchFieldException, NoSuchMethodException, InstantiationException, SecurityException, IllegalArgumentException, InvocationTargetException {
        String str = c;
        Intrinsics.checkNotNullParameter(activity, "activity");
        Rect rect = new Rect();
        Configuration configuration = activity.getResources().getConfiguration();
        DisplayCutout displayCutout = null;
        try {
            Field declaredField = Configuration.class.getDeclaredField("windowConfiguration");
            declaredField.setAccessible(true);
            Object obj = declaredField.get(configuration);
            Intrinsics.checkNotNullParameter(activity, "activity");
            if (activity.isInMultiWindowMode()) {
                Object objInvoke = obj.getClass().getDeclaredMethod("getBounds", null).invoke(obj, null);
                Intrinsics.e(objInvoke, "null cannot be cast to non-null type android.graphics.Rect");
                rect.set((Rect) objInvoke);
            } else {
                Object objInvoke2 = obj.getClass().getDeclaredMethod("getAppBounds", null).invoke(obj, null);
                Intrinsics.e(objInvoke2, "null cannot be cast to non-null type android.graphics.Rect");
                rect.set((Rect) objInvoke2);
            }
        } catch (IllegalAccessException e) {
            Log.w(str, e);
            activity.getWindowManager().getDefaultDisplay().getRectSize(rect);
        } catch (NoSuchFieldException e2) {
            Log.w(str, e2);
            activity.getWindowManager().getDefaultDisplay().getRectSize(rect);
        } catch (NoSuchMethodException e3) {
            Log.w(str, e3);
            activity.getWindowManager().getDefaultDisplay().getRectSize(rect);
        } catch (InvocationTargetException e4) {
            Log.w(str, e4);
            activity.getWindowManager().getDefaultDisplay().getRectSize(rect);
        }
        Display currentDisplay = activity.getWindowManager().getDefaultDisplay();
        Point point = new Point();
        currentDisplay.getRealSize(point);
        Intrinsics.checkNotNullParameter(activity, "activity");
        if (!activity.isInMultiWindowMode()) {
            Resources resources = activity.getResources();
            int identifier = resources.getIdentifier("navigation_bar_height", "dimen", DtbConstants.NATIVE_OS_NAME);
            int dimensionPixelSize = identifier > 0 ? resources.getDimensionPixelSize(identifier) : 0;
            int i = rect.bottom + dimensionPixelSize;
            if (i == point.y) {
                rect.bottom = i;
            } else {
                int i2 = rect.right + dimensionPixelSize;
                if (i2 == point.x) {
                    rect.right = i2;
                } else if (rect.left == dimensionPixelSize) {
                    rect.left = 0;
                }
            }
        }
        if (rect.width() < point.x || rect.height() < point.y) {
            Intrinsics.checkNotNullParameter(activity, "activity");
            if (!activity.isInMultiWindowMode()) {
                Intrinsics.checkNotNullExpressionValue(currentDisplay, "currentDisplay");
                try {
                    Constructor<?> constructor = Class.forName("android.view.DisplayInfo").getConstructor(null);
                    constructor.setAccessible(true);
                    Object objNewInstance = constructor.newInstance(null);
                    Method declaredMethod = currentDisplay.getClass().getDeclaredMethod("getDisplayInfo", objNewInstance.getClass());
                    declaredMethod.setAccessible(true);
                    declaredMethod.invoke(currentDisplay, objNewInstance);
                    Field declaredField2 = objNewInstance.getClass().getDeclaredField("displayCutout");
                    declaredField2.setAccessible(true);
                    Object obj2 = declaredField2.get(objNewInstance);
                    if (f.x(obj2)) {
                        displayCutout = f.i(obj2);
                    }
                } catch (ClassNotFoundException e5) {
                    Log.w(str, e5);
                } catch (IllegalAccessException e6) {
                    Log.w(str, e6);
                } catch (InstantiationException e7) {
                    Log.w(str, e7);
                } catch (NoSuchFieldException e8) {
                    Log.w(str, e8);
                } catch (NoSuchMethodException e9) {
                    Log.w(str, e9);
                } catch (InvocationTargetException e10) {
                    Log.w(str, e10);
                }
                if (displayCutout != null) {
                    int i3 = rect.left;
                    Intrinsics.checkNotNullParameter(displayCutout, "displayCutout");
                    if (i3 == displayCutout.getSafeInsetLeft()) {
                        rect.left = 0;
                    }
                    int i4 = point.x - rect.right;
                    Intrinsics.checkNotNullParameter(displayCutout, "displayCutout");
                    if (i4 == displayCutout.getSafeInsetRight()) {
                        int i5 = rect.right;
                        Intrinsics.checkNotNullParameter(displayCutout, "displayCutout");
                        rect.right = displayCutout.getSafeInsetRight() + i5;
                    }
                    int i6 = rect.top;
                    Intrinsics.checkNotNullParameter(displayCutout, "displayCutout");
                    if (i6 == displayCutout.getSafeInsetTop()) {
                        rect.top = 0;
                    }
                    int i7 = point.y - rect.bottom;
                    Intrinsics.checkNotNullParameter(displayCutout, "displayCutout");
                    if (i7 == displayCutout.getSafeInsetBottom()) {
                        int i8 = rect.bottom;
                        Intrinsics.checkNotNullParameter(displayCutout, "displayCutout");
                        rect.bottom = displayCutout.getSafeInsetBottom() + i8;
                    }
                }
            }
        }
        return rect;
    }
}

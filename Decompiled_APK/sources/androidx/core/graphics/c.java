package androidx.core.graphics;

import android.app.ForegroundServiceStartNotAllowedException;
import android.app.Notification;
import android.graphics.BlendMode;
import android.graphics.Insets;
import android.os.Trace;
import android.util.Log;
import androidx.work.impl.foreground.SystemForegroundService;
import androidx.work.z;
import com.comscore.streaming.EventType;

/* loaded from: classes.dex */
public abstract class c {
    public static boolean a() {
        return Trace.isEnabled();
    }

    public static Object b(a aVar) {
        switch (b.a[aVar.ordinal()]) {
            case 1:
                return BlendMode.CLEAR;
            case 2:
                return BlendMode.SRC;
            case 3:
                return BlendMode.DST;
            case 4:
                return BlendMode.SRC_OVER;
            case 5:
                return BlendMode.DST_OVER;
            case 6:
                return BlendMode.SRC_IN;
            case 7:
                return BlendMode.DST_IN;
            case 8:
                return BlendMode.SRC_OUT;
            case 9:
                return BlendMode.DST_OUT;
            case 10:
                return BlendMode.SRC_ATOP;
            case 11:
                return BlendMode.DST_ATOP;
            case 12:
                return BlendMode.XOR;
            case 13:
                return BlendMode.PLUS;
            case 14:
                return BlendMode.MODULATE;
            case 15:
                return BlendMode.SCREEN;
            case 16:
                return BlendMode.OVERLAY;
            case 17:
                return BlendMode.DARKEN;
            case 18:
                return BlendMode.LIGHTEN;
            case 19:
                return BlendMode.COLOR_DODGE;
            case 20:
                return BlendMode.COLOR_BURN;
            case 21:
                return BlendMode.HARD_LIGHT;
            case EventType.WINDOW_STATE /* 22 */:
                return BlendMode.SOFT_LIGHT;
            case EventType.AUDIO /* 23 */:
                return BlendMode.DIFFERENCE;
            case EventType.VIDEO /* 24 */:
                return BlendMode.EXCLUSION;
            case EventType.SUBS /* 25 */:
                return BlendMode.MULTIPLY;
            case EventType.CDN /* 26 */:
                return BlendMode.HUE;
            case 27:
                return BlendMode.SATURATION;
            case 28:
                return BlendMode.COLOR;
            case 29:
                return BlendMode.LUMINOSITY;
            default:
                return null;
        }
    }

    public static Insets c(int i, int i2, int i3, int i4) {
        return Insets.of(i, i2, i3, i4);
    }

    public static void d(com.airbnb.lottie.animation.a aVar, Object obj) {
        aVar.setBlendMode((BlendMode) obj);
    }

    public static void e(SystemForegroundService systemForegroundService, int i, Notification notification, int i2) {
        systemForegroundService.startForeground(i, notification, i2);
    }

    public static void f(SystemForegroundService systemForegroundService, int i, Notification notification, int i2) {
        try {
            systemForegroundService.startForeground(i, notification, i2);
        } catch (ForegroundServiceStartNotAllowedException e) {
            z zVarC = z.c();
            String str = SystemForegroundService.e;
            if (zVarC.a <= 5) {
                Log.w(str, "Unable to start foreground service", e);
            }
        } catch (SecurityException e2) {
            z zVarC2 = z.c();
            String str2 = SystemForegroundService.e;
            if (zVarC2.a <= 5) {
                Log.w(str2, "Unable to start foreground service", e2);
            }
        }
    }
}

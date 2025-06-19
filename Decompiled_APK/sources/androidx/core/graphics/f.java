package androidx.core.graphics;

import android.graphics.PorterDuff;
import android.graphics.PorterDuffXfermode;
import android.os.Build;

/* loaded from: classes.dex */
public abstract class f {
    public static final /* synthetic */ int a = 0;

    static {
        new ThreadLocal();
    }

    public static void a(com.airbnb.lottie.animation.a aVar, a aVar2) {
        PorterDuff.Mode mode;
        if (Build.VERSION.SDK_INT >= 29) {
            c.d(aVar, aVar2 != null ? c.b(aVar2) : null);
            return;
        }
        if (aVar2 == null) {
            aVar.setXfermode(null);
            return;
        }
        switch (b.a[aVar2.ordinal()]) {
            case 1:
                mode = PorterDuff.Mode.CLEAR;
                break;
            case 2:
                mode = PorterDuff.Mode.SRC;
                break;
            case 3:
                mode = PorterDuff.Mode.DST;
                break;
            case 4:
                mode = PorterDuff.Mode.SRC_OVER;
                break;
            case 5:
                mode = PorterDuff.Mode.DST_OVER;
                break;
            case 6:
                mode = PorterDuff.Mode.SRC_IN;
                break;
            case 7:
                mode = PorterDuff.Mode.DST_IN;
                break;
            case 8:
                mode = PorterDuff.Mode.SRC_OUT;
                break;
            case 9:
                mode = PorterDuff.Mode.DST_OUT;
                break;
            case 10:
                mode = PorterDuff.Mode.SRC_ATOP;
                break;
            case 11:
                mode = PorterDuff.Mode.DST_ATOP;
                break;
            case 12:
                mode = PorterDuff.Mode.XOR;
                break;
            case 13:
                mode = PorterDuff.Mode.ADD;
                break;
            case 14:
                mode = PorterDuff.Mode.MULTIPLY;
                break;
            case 15:
                mode = PorterDuff.Mode.SCREEN;
                break;
            case 16:
                mode = PorterDuff.Mode.OVERLAY;
                break;
            case 17:
                mode = PorterDuff.Mode.DARKEN;
                break;
            case 18:
                mode = PorterDuff.Mode.LIGHTEN;
                break;
            default:
                mode = null;
                break;
        }
        aVar.setXfermode(mode != null ? new PorterDuffXfermode(mode) : null);
    }
}

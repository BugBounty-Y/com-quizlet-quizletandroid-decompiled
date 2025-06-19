package androidx.camera.core.internal.utils;

import android.util.Size;
import com.amazon.device.ads.DtbConstants;

/* loaded from: classes.dex */
public abstract class a {
    public static final Size a = new Size(0, 0);
    public static final Size b;
    public static final Size c;
    public static final Size d;
    public static final Size e;
    public static final Size f;

    static {
        new Size(DtbConstants.DEFAULT_PLAYER_WIDTH, 240);
        b = new Size(640, DtbConstants.DEFAULT_PLAYER_HEIGHT);
        c = new Size(720, DtbConstants.DEFAULT_PLAYER_HEIGHT);
        d = new Size(1280, 720);
        e = new Size(1920, 1080);
        f = new Size(1920, 1440);
    }

    public static int a(Size size) {
        return size.getHeight() * size.getWidth();
    }
}

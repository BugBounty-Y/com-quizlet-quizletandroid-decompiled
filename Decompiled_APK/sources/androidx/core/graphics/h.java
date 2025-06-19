package androidx.core.graphics;

import android.content.res.Resources;
import android.os.Build;
import android.os.Trace;
import androidx.collection.C0220s;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3161h6;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3359k2;

/* loaded from: classes.dex */
public abstract class h {
    public static final AbstractC3161h6 a;
    public static final C0220s b;

    static {
        Trace.beginSection(AbstractC3359k2.f("TypefaceCompat static init"));
        int i = Build.VERSION.SDK_INT;
        if (i >= 29) {
            a = new k();
        } else if (i >= 28) {
            a = new j();
        } else {
            a = new i();
        }
        b = new C0220s(16);
        Trace.endSection();
    }

    /* JADX WARN: Removed duplicated region for block: B:14:0x0033  */
    /* JADX WARN: Removed duplicated region for block: B:16:0x0036  */
    /* JADX WARN: Removed duplicated region for block: B:19:0x004a  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static android.graphics.Typeface a(android.content.Context r16, androidx.core.content.res.d r17, android.content.res.Resources r18, int r19, java.lang.String r20, int r21, int r22, androidx.core.content.res.b r23, boolean r24) {
        /*
            Method dump skipped, instructions count: 517
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.core.graphics.h.a(android.content.Context, androidx.core.content.res.d, android.content.res.Resources, int, java.lang.String, int, int, androidx.core.content.res.b, boolean):android.graphics.Typeface");
    }

    public static String b(Resources resources, int i, String str, int i2, int i3) {
        return resources.getResourcePackageName(i) + '-' + str + '-' + i2 + '-' + i + '-' + i3;
    }
}

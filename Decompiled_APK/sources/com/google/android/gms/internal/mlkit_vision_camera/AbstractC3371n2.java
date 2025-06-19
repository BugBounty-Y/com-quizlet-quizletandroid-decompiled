package com.google.android.gms.internal.mlkit_vision_camera;

import android.util.Log;
import android.view.View;
import androidx.appcompat.widget.C0122z;
import java.lang.reflect.Field;
import java.net.ProtocolException;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_camera.n2, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3371n2 {
    public static boolean a = true;
    public static Field b;
    public static boolean c;
    public static final /* synthetic */ int d = 0;

    public static C0122z b(String statusLine) {
        int i;
        String strSubstring;
        Intrinsics.checkNotNullParameter(statusLine, "statusLine");
        boolean zR = kotlin.text.D.r(statusLine, "HTTP/1.", false);
        okhttp3.B b2 = okhttp3.B.HTTP_1_0;
        if (zR) {
            i = 9;
            if (statusLine.length() < 9 || statusLine.charAt(8) != ' ') {
                throw new ProtocolException("Unexpected status line: ".concat(statusLine));
            }
            int iCharAt = statusLine.charAt(7) - '0';
            if (iCharAt != 0) {
                if (iCharAt != 1) {
                    throw new ProtocolException("Unexpected status line: ".concat(statusLine));
                }
                b2 = okhttp3.B.HTTP_1_1;
            }
        } else {
            if (!kotlin.text.D.r(statusLine, "ICY ", false)) {
                throw new ProtocolException("Unexpected status line: ".concat(statusLine));
            }
            i = 4;
        }
        int i2 = i + 3;
        if (statusLine.length() < i2) {
            throw new ProtocolException("Unexpected status line: ".concat(statusLine));
        }
        try {
            String strSubstring2 = statusLine.substring(i, i2);
            Intrinsics.checkNotNullExpressionValue(strSubstring2, "this as java.lang.String…ing(startIndex, endIndex)");
            int i3 = Integer.parseInt(strSubstring2);
            if (statusLine.length() <= i2) {
                strSubstring = "";
            } else {
                if (statusLine.charAt(i2) != ' ') {
                    throw new ProtocolException("Unexpected status line: ".concat(statusLine));
                }
                strSubstring = statusLine.substring(i + 4);
                Intrinsics.checkNotNullExpressionValue(strSubstring, "this as java.lang.String).substring(startIndex)");
            }
            return new C0122z(b2, i3, strSubstring);
        } catch (NumberFormatException unused) {
            throw new ProtocolException("Unexpected status line: ".concat(statusLine));
        }
    }

    public float a(View view) {
        if (a) {
            try {
                return androidx.transition.M.a(view);
            } catch (NoSuchMethodError unused) {
                a = false;
            }
        }
        return view.getAlpha();
    }

    public void c(View view, float f) {
        if (a) {
            try {
                androidx.transition.M.b(view, f);
                return;
            } catch (NoSuchMethodError unused) {
                a = false;
            }
        }
        view.setAlpha(f);
    }

    public void d(View view, int i) throws IllegalAccessException, NoSuchFieldException, SecurityException, IllegalArgumentException {
        if (!c) {
            try {
                Field declaredField = View.class.getDeclaredField("mViewFlags");
                b = declaredField;
                declaredField.setAccessible(true);
            } catch (NoSuchFieldException unused) {
                Log.i("ViewUtilsApi19", "fetchViewFlagsField: ");
            }
            c = true;
        }
        Field field = b;
        if (field != null) {
            try {
                b.setInt(view, i | (field.getInt(view) & (-13)));
            } catch (IllegalAccessException unused2) {
            }
        }
    }
}

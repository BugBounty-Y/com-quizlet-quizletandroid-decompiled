package com.google.android.gms.internal.gtm;

import android.support.v4.media.session.a;
import androidx.camera.camera2.internal.AbstractC0147y;
import com.j256.ormlite.stmt.query.SimpleComparison;
import java.util.logging.Level;
import java.util.logging.Logger;

/* loaded from: classes2.dex */
public abstract class zzte {
    public static String zza(String str, Object... objArr) {
        int length;
        int length2;
        int iIndexOf;
        String strE;
        int i = 0;
        int i2 = 0;
        while (true) {
            length = objArr.length;
            if (i2 >= length) {
                break;
            }
            Object obj = objArr[i2];
            if (obj == null) {
                strE = "null";
            } else {
                try {
                    strE = obj.toString();
                } catch (Exception e) {
                    String strL = a.l(obj.getClass().getName(), "@", Integer.toHexString(System.identityHashCode(obj)));
                    Logger.getLogger("com.google.common.base.Strings").logp(Level.WARNING, "com.google.common.base.Strings", "lenientToString", "Exception during lenientFormat for ".concat(strL), (Throwable) e);
                    strE = AbstractC0147y.e(SimpleComparison.LESS_THAN_OPERATION, strL, " threw ", e.getClass().getName(), SimpleComparison.GREATER_THAN_OPERATION);
                }
            }
            objArr[i2] = strE;
            i2++;
        }
        StringBuilder sb = new StringBuilder(str.length() + (length * 16));
        int i3 = 0;
        while (true) {
            length2 = objArr.length;
            if (i >= length2 || (iIndexOf = str.indexOf("%s", i3)) == -1) {
                break;
            }
            sb.append((CharSequence) str, i3, iIndexOf);
            sb.append(objArr[i]);
            i++;
            i3 = iIndexOf + 2;
        }
        sb.append((CharSequence) str, i3, str.length());
        if (i < length2) {
            sb.append(" [");
            sb.append(objArr[i]);
            for (int i4 = i + 1; i4 < objArr.length; i4++) {
                sb.append(", ");
                sb.append(objArr[i4]);
            }
            sb.append(']');
        }
        return sb.toString();
    }
}

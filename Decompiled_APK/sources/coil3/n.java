package coil3;

import android.content.res.Resources;
import android.graphics.drawable.BitmapDrawable;
import android.graphics.drawable.Drawable;
import androidx.appcompat.widget.C0073b;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import java.util.ArrayList;
import java.util.List;
import kotlin.collections.CollectionsKt;
import kotlin.collections.K;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.CharsKt;
import kotlin.text.D;
import kotlin.text.StringsKt;

/* loaded from: classes.dex */
public abstract class n {
    public static final androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableList.e a = new androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableList.e(Boolean.TRUE);

    public static y a(String str) {
        String str2 = okio.x.b;
        StringBuilder sb = new StringBuilder();
        sb.append("file");
        sb.append(':');
        if (str != null) {
            sb.append(str);
        }
        return new y(sb.toString(), str2, "file", null, str);
    }

    public static final Drawable b(j jVar, Resources resources) {
        return jVar instanceof e ? ((e) jVar).a : jVar instanceof a ? new BitmapDrawable(resources, ((a) jVar).a) : new C0073b(jVar, 1);
    }

    public static final j c(Drawable drawable) {
        return drawable instanceof BitmapDrawable ? new a(((BitmapDrawable) drawable).getBitmap()) : new e(drawable);
    }

    public static final Object d(coil3.request.g gVar, androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableList.e eVar) {
        Object obj = gVar.r.a.get(eVar);
        if (obj != null) {
            return obj;
        }
        Object obj2 = gVar.t.n.a.get(eVar);
        return obj2 == null ? eVar.a : obj2;
    }

    public static final Object e(coil3.request.m mVar, androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableList.e eVar) {
        Object obj = mVar.j.a.get(eVar);
        return obj == null ? eVar.a : obj;
    }

    public static final String f(y yVar) {
        List listG = g(yVar);
        if (listG.isEmpty()) {
            return null;
        }
        String str = yVar.e;
        Intrinsics.d(str);
        String str2 = yVar.b;
        if (!D.r(str, str2, false)) {
            str2 = "";
        }
        return CollectionsKt.S(listG, yVar.b, str2, null, null, 60);
    }

    public static final List g(y yVar) {
        String str = yVar.e;
        if (str == null) {
            return K.a;
        }
        ArrayList arrayList = new ArrayList();
        int i = -1;
        while (i < str.length()) {
            int i2 = i + 1;
            int iL = StringsKt.L(str, '/', i2, false, 4);
            if (iL == -1) {
                iL = str.length();
            }
            String strSubstring = str.substring(i2, iL);
            Intrinsics.checkNotNullExpressionValue(strSubstring, "substring(...)");
            if (strSubstring.length() > 0) {
                arrayList.add(strSubstring);
            }
            i = iL;
        }
        return arrayList;
    }

    public static final String h(String str, byte[] bArr) {
        int length = str.length();
        int i = 0;
        int iMax = Math.max(0, length - 2);
        int i2 = 0;
        while (true) {
            if (i >= iMax) {
                if (i == i2) {
                    return str;
                }
                if (i >= length) {
                    return D.j(i2, bArr, 5);
                }
            } else if (str.charAt(i) == '%') {
                int i3 = i + 3;
                try {
                    String strSubstring = str.substring(i + 1, i3);
                    Intrinsics.checkNotNullExpressionValue(strSubstring, "substring(...)");
                    bArr[i2] = (byte) Integer.parseInt(strSubstring, CharsKt.checkRadix(16));
                    i2++;
                    i = i3;
                } catch (NumberFormatException unused) {
                }
            }
            bArr[i2] = (byte) str.charAt(i);
            i2++;
            i++;
        }
    }

    public static y i(String str) {
        String strSubstring;
        String strSubstring2;
        String strSubstring3;
        String strSubstring4;
        String strSubstring5;
        String str2 = okio.x.b;
        String strO = !Intrinsics.b(str2, "/") ? D.o(str, str2, "/", false) : str;
        boolean z = true;
        int i = 0;
        int i2 = -1;
        int i3 = -1;
        int i4 = -1;
        int i5 = -1;
        int i6 = -1;
        while (i < strO.length()) {
            char cCharAt = strO.charAt(i);
            if (cCharAt != '#') {
                if (cCharAt != '/') {
                    if (cCharAt != ':') {
                        if (cCharAt == '?' && i4 == -1 && i2 == -1) {
                            i4 = i + 1;
                        }
                    } else if (z && i4 == -1 && i2 == -1) {
                        int i7 = i + 2;
                        if (i7 < str.length() && str.charAt(i + 1) == '/' && str.charAt(i7) == '/') {
                            i5 = i + 3;
                            z = false;
                            i6 = i;
                            i = i7;
                        } else if (strO.equals(str)) {
                            i3 = i + 1;
                            i6 = i;
                            i = i3;
                            i5 = i;
                        }
                    }
                } else if (i3 == -1 && i4 == -1 && i2 == -1) {
                    i3 = i5 == -1 ? 0 : i;
                    z = false;
                }
            } else if (i2 == -1) {
                i2 = i + 1;
            }
            i++;
        }
        int i8 = SubsamplingScaleImageView.TILE_SIZE_AUTO;
        int iMin = Math.min(i2 == -1 ? Integer.MAX_VALUE : i2 - 1, strO.length());
        int iMin2 = Math.min(i4 == -1 ? Integer.MAX_VALUE : i4 - 1, iMin);
        if (i5 != -1) {
            strSubstring2 = strO.substring(0, i6);
            Intrinsics.checkNotNullExpressionValue(strSubstring2, "substring(...)");
            if (i3 != -1) {
                i8 = i3;
            }
            strSubstring = strO.substring(i5, Math.min(i8, iMin2));
            Intrinsics.checkNotNullExpressionValue(strSubstring, "substring(...)");
        } else {
            strSubstring = null;
            strSubstring2 = null;
        }
        if (i3 != -1) {
            strSubstring3 = strO.substring(i3, iMin2);
            Intrinsics.checkNotNullExpressionValue(strSubstring3, "substring(...)");
        } else {
            strSubstring3 = null;
        }
        if (i4 != -1) {
            strSubstring4 = strO.substring(i4, iMin);
            Intrinsics.checkNotNullExpressionValue(strSubstring4, "substring(...)");
        } else {
            strSubstring4 = null;
        }
        if (i2 != -1) {
            strSubstring5 = strO.substring(i2, strO.length());
            Intrinsics.checkNotNullExpressionValue(strSubstring5, "substring(...)");
        } else {
            strSubstring5 = null;
        }
        byte[] bArr = new byte[Math.max(0, Math.max(strSubstring2 != null ? strSubstring2.length() : 0, Math.max(strSubstring != null ? strSubstring.length() : 0, Math.max(strSubstring3 != null ? strSubstring3.length() : 0, Math.max(strSubstring4 != null ? strSubstring4.length() : 0, strSubstring5 != null ? strSubstring5.length() : 0)))) - 2)];
        String str3 = strSubstring4;
        String strH = strSubstring2 != null ? h(strSubstring2, bArr) : null;
        String strH2 = strSubstring != null ? h(strSubstring, bArr) : null;
        String strH3 = strSubstring3 != null ? h(strSubstring3, bArr) : null;
        if (str3 != null) {
            h(str3, bArr);
        }
        if (strSubstring5 != null) {
            h(strSubstring5, bArr);
        }
        return new y(strO, str2, strH, strH2, strH3);
    }
}

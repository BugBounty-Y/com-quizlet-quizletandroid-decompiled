package androidx.core.provider;

import android.content.Context;
import android.content.pm.PackageManager;
import android.graphics.Typeface;
import android.os.Build;
import android.os.Trace;
import androidx.collection.C0220s;
import androidx.collection.V;
import com.android.billingclient.api.s;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3161h6;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3359k2;
import com.pubmatic.sdk.video.c;
import java.util.List;
import java.util.concurrent.LinkedBlockingDeque;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

/* loaded from: classes.dex */
public abstract class g {
    public static final C0220s a = new C0220s(16);
    public static final ThreadPoolExecutor b;
    public static final Object c;
    public static final V d;

    static {
        ThreadPoolExecutor threadPoolExecutor = new ThreadPoolExecutor(0, 1, c.a.DEFAULT_MEDIA_URI_TIMEOUT, TimeUnit.MILLISECONDS, new LinkedBlockingDeque(), new androidx.camera.core.impl.utils.executor.f(1));
        threadPoolExecutor.allowCoreThreadTimeOut(true);
        b = threadPoolExecutor;
        c = new Object();
        d = new V(0);
    }

    public static String a(int i, List list) {
        StringBuilder sb = new StringBuilder();
        for (int i2 = 0; i2 < list.size(); i2++) {
            sb.append(((d) list.get(i2)).e);
            sb.append("-");
            sb.append(i);
            if (i2 < list.size() - 1) {
                sb.append(";");
            }
        }
        return sb.toString();
    }

    public static f b(String str, Context context, List list, int i) {
        int i2;
        Typeface typefaceC;
        Trace.beginSection(AbstractC3359k2.f("getFontSync"));
        C0220s c0220s = a;
        try {
            Typeface typeface = (Typeface) c0220s.g(str);
            if (typeface != null) {
                return new f(typeface);
            }
            s sVarA = c.a(context, list);
            int i3 = sVarA.b;
            List list2 = (List) sVarA.c;
            if (i3 != 0) {
                i2 = i3 != 1 ? -3 : -2;
            } else {
                h[] hVarArr = (h[]) list2.get(0);
                if (hVarArr == null || hVarArr.length == 0) {
                    i2 = 1;
                } else {
                    int length = hVarArr.length;
                    int i4 = 0;
                    while (true) {
                        if (i4 >= length) {
                            i2 = 0;
                            break;
                        }
                        int i5 = hVarArr[i4].e;
                        if (i5 == 0) {
                            i4++;
                        } else if (i5 >= 0) {
                            i2 = i5;
                        }
                    }
                }
            }
            if (i2 != 0) {
                return new f(i2);
            }
            if (list2.size() <= 1 || Build.VERSION.SDK_INT < 29) {
                h[] hVarArr2 = (h[]) list2.get(0);
                AbstractC3161h6 abstractC3161h6 = androidx.core.graphics.h.a;
                Trace.beginSection(AbstractC3359k2.f("TypefaceCompat.createFromFontInfo"));
                typefaceC = androidx.core.graphics.h.a.c(context, hVarArr2, i);
                Trace.endSection();
            } else {
                AbstractC3161h6 abstractC3161h62 = androidx.core.graphics.h.a;
                Trace.beginSection(AbstractC3359k2.f("TypefaceCompat.createFromFontInfoWithFallback"));
                typefaceC = androidx.core.graphics.h.a.d(context, list2, i);
                Trace.endSection();
            }
            if (typefaceC == null) {
                return new f(-3);
            }
            c0220s.k(str, typefaceC);
            return new f(typefaceC);
        } catch (PackageManager.NameNotFoundException unused) {
            return new f(-1);
        } catch (Throwable th) {
            throw th;
        } finally {
            Trace.endSection();
        }
    }
}

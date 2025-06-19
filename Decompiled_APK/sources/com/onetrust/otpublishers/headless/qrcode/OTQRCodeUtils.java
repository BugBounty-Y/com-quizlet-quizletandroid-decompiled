package com.onetrust.otpublishers.headless.qrcode;

import android.graphics.Bitmap;
import android.graphics.Color;
import android.util.DisplayMetrics;
import android.widget.ImageView;
import androidx.fragment.app.I;
import com.google.zxing.a;
import com.google.zxing.common.b;
import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;
import java.util.EnumMap;

/* loaded from: classes2.dex */
public final class OTQRCodeUtils {
    private OTQRCodeUtils() {
    }

    public static b a(int i, int i2, String str, boolean z) {
        int i3 = z ? 1 : 2;
        try {
            EnumMap enumMap = new EnumMap(a.class);
            enumMap.put((EnumMap) a.b, (a) "UTF-8");
            enumMap.put((EnumMap) a.f, (a) Integer.valueOf(i3));
            return new com.quizlet.shared.usecase.folderstudymaterials.a(20).l(str, 12, i2, i, enumMap);
        } catch (Exception e) {
            OTLogger.c("OTQRCodeUtils", 6, "encodeToBitmap(): " + e);
            return null;
        }
    }

    public static void b(String str, I i, String str2, String str3, ImageView imageView, boolean z) {
        try {
            i.getWindowManager().getDefaultDisplay().getMetrics(new DisplayMetrics());
            int i2 = (int) (r0.widthPixels * 0.2d);
            b bVarA = a((int) (r0.heightPixels * 0.3d), i2, str, z);
            if (bVarA == null) {
                OTLogger.c("OTQRCodeUtils", 6, "encodeToBitmap(): null bitMatrix");
                return;
            }
            int i3 = bVarA.a;
            int i4 = bVarA.b;
            int[] iArr = new int[i3 * i4];
            if (com.onetrust.otpublishers.headless.Internal.a.j(str2) || com.onetrust.otpublishers.headless.Internal.a.j(str3)) {
                return;
            }
            int color = Color.parseColor(str2);
            int color2 = Color.parseColor(str3);
            for (int i5 = 0; i5 < i4; i5++) {
                int i6 = i5 * i3;
                for (int i7 = 0; i7 < i3; i7++) {
                    iArr[i6 + i7] = bVarA.b(i7, i5) ? color2 : color;
                }
            }
            Bitmap bitmapCreateBitmap = Bitmap.createBitmap(i3, i4, Bitmap.Config.ARGB_8888);
            bitmapCreateBitmap.setPixels(iArr, 0, i2, 0, 0, i3, i4);
            imageView.setImageBitmap(bitmapCreateBitmap);
        } catch (Exception e) {
            OTLogger.c("OTQRCodeUtils", 6, "encodeToBitmap(): " + e);
        }
    }
}

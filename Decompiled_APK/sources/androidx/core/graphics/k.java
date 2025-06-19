package androidx.core.graphics;

import android.content.ContentResolver;
import android.content.Context;
import android.content.res.Resources;
import android.graphics.Typeface;
import android.graphics.fonts.Font;
import android.graphics.fonts.FontFamily;
import android.graphics.fonts.FontStyle;
import android.os.ParcelFileDescriptor;
import android.util.Log;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3161h6;
import java.io.IOException;
import java.util.List;

/* loaded from: classes.dex */
public final class k extends AbstractC3161h6 {
    public static Font j(FontFamily fontFamily, int i) {
        FontStyle fontStyle = new FontStyle((i & 1) != 0 ? 700 : 400, (i & 2) != 0 ? 1 : 0);
        Font font = fontFamily.getFont(0);
        int iL = l(fontStyle, font.getStyle());
        for (int i2 = 1; i2 < fontFamily.getSize(); i2++) {
            Font font2 = fontFamily.getFont(i2);
            int iL2 = l(fontStyle, font2.getStyle());
            if (iL2 < iL) {
                font = font2;
                iL = iL2;
            }
        }
        return font;
    }

    public static FontFamily k(androidx.core.provider.h[] hVarArr, ContentResolver contentResolver) throws IOException {
        ParcelFileDescriptor parcelFileDescriptorOpenFileDescriptor;
        FontFamily.Builder builder = null;
        for (androidx.core.provider.h hVar : hVarArr) {
            try {
                parcelFileDescriptorOpenFileDescriptor = contentResolver.openFileDescriptor(hVar.a, "r", null);
            } catch (IOException e) {
                Log.w("TypefaceCompatApi29Impl", "Font load failed", e);
            }
            if (parcelFileDescriptorOpenFileDescriptor == null) {
                if (parcelFileDescriptorOpenFileDescriptor != null) {
                }
            } else {
                try {
                    Font fontBuild = new Font.Builder(parcelFileDescriptorOpenFileDescriptor).setWeight(hVar.c).setSlant(hVar.d ? 1 : 0).setTtcIndex(hVar.b).build();
                    if (builder == null) {
                        builder = new FontFamily.Builder(fontBuild);
                    } else {
                        builder.addFont(fontBuild);
                    }
                } catch (Throwable th) {
                    try {
                        parcelFileDescriptorOpenFileDescriptor.close();
                    } catch (Throwable th2) {
                        th.addSuppressed(th2);
                    }
                    throw th;
                }
            }
            parcelFileDescriptorOpenFileDescriptor.close();
        }
        if (builder == null) {
            return null;
        }
        return builder.build();
    }

    public static int l(FontStyle fontStyle, FontStyle fontStyle2) {
        return (Math.abs(fontStyle.getWeight() - fontStyle2.getWeight()) / 100) + (fontStyle.getSlant() == fontStyle2.getSlant() ? 0 : 2);
    }

    @Override // com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3161h6
    public final Typeface b(Context context, androidx.core.content.res.e eVar, Resources resources, int i) throws IOException {
        try {
            FontFamily.Builder builder = null;
            for (androidx.core.content.res.f fVar : eVar.a) {
                try {
                    Font fontBuild = new Font.Builder(resources, fVar.f).setWeight(fVar.b).setSlant(fVar.c ? 1 : 0).setTtcIndex(fVar.e).setFontVariationSettings(fVar.d).build();
                    if (builder == null) {
                        builder = new FontFamily.Builder(fontBuild);
                    } else {
                        builder.addFont(fontBuild);
                    }
                } catch (IOException unused) {
                }
            }
            if (builder == null) {
                return null;
            }
            FontFamily fontFamilyBuild = builder.build();
            return new Typeface.CustomFallbackBuilder(fontFamilyBuild).setStyle(j(fontFamilyBuild, i).getStyle()).build();
        } catch (Exception e) {
            Log.w("TypefaceCompatApi29Impl", "Font load failed", e);
            return null;
        }
    }

    @Override // com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3161h6
    public final Typeface c(Context context, androidx.core.provider.h[] hVarArr, int i) {
        try {
            FontFamily fontFamilyK = k(hVarArr, context.getContentResolver());
            if (fontFamilyK == null) {
                return null;
            }
            return new Typeface.CustomFallbackBuilder(fontFamilyK).setStyle(j(fontFamilyK, i).getStyle()).build();
        } catch (Exception e) {
            Log.w("TypefaceCompatApi29Impl", "Font load failed", e);
            return null;
        }
    }

    @Override // com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3161h6
    public final Typeface d(Context context, List list, int i) {
        ContentResolver contentResolver = context.getContentResolver();
        try {
            FontFamily fontFamilyK = k((androidx.core.provider.h[]) list.get(0), contentResolver);
            if (fontFamilyK == null) {
                return null;
            }
            Typeface.CustomFallbackBuilder customFallbackBuilder = new Typeface.CustomFallbackBuilder(fontFamilyK);
            for (int i2 = 1; i2 < list.size(); i2++) {
                FontFamily fontFamilyK2 = k((androidx.core.provider.h[]) list.get(i2), contentResolver);
                if (fontFamilyK2 != null) {
                    customFallbackBuilder.addCustomFallback(fontFamilyK2);
                }
            }
            return customFallbackBuilder.setStyle(j(fontFamilyK, i).getStyle()).build();
        } catch (Exception e) {
            Log.w("TypefaceCompatApi29Impl", "Font load failed", e);
            return null;
        }
    }

    @Override // com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3161h6
    public final Typeface e(Context context, Resources resources, int i, String str, int i2) throws IOException {
        try {
            Font fontBuild = new Font.Builder(resources, i).build();
            return new Typeface.CustomFallbackBuilder(new FontFamily.Builder(fontBuild).build()).setStyle(fontBuild.getStyle()).build();
        } catch (Exception e) {
            Log.w("TypefaceCompatApi29Impl", "Font load failed", e);
            return null;
        }
    }

    @Override // com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3161h6
    public final androidx.core.provider.h f(androidx.core.provider.h[] hVarArr, int i) {
        throw new RuntimeException("Do not use this function in API 29 or later.");
    }
}

package coil3.network;

import android.os.Build;
import android.os.ext.SdkExtensions;
import android.provider.MediaStore;
import androidx.camera.camera2.internal.AbstractC0147y;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public abstract class g {
    public static final /* synthetic */ int a = 0;

    public static androidx.activity.result.j a() {
        androidx.activity.result.contract.f mediaType = androidx.activity.result.contract.f.a;
        androidx.activity.result.contract.e eVar = androidx.activity.result.contract.e.a;
        int i = Build.VERSION.SDK_INT;
        int pickImagesMaxLimit = SubsamplingScaleImageView.TILE_SIZE_AUTO;
        int pickImagesMaxLimit2 = (i < 33 && (i < 30 || SdkExtensions.getExtensionVersion(30) < 2)) ? Integer.MAX_VALUE : MediaStore.getPickImagesMaxLimit();
        androidx.activity.result.contract.d defaultTab = androidx.activity.result.contract.d.a;
        Intrinsics.checkNotNullParameter(mediaType, "mediaType");
        Intrinsics.checkNotNullParameter(defaultTab, "defaultTab");
        if (i >= 33 || (i >= 30 && SdkExtensions.getExtensionVersion(30) >= 2)) {
            MediaStore.getPickImagesMaxLimit();
        }
        Intrinsics.checkNotNullParameter(mediaType, "mediaType");
        Intrinsics.checkNotNullParameter(defaultTab, "defaultTab");
        androidx.activity.result.j jVar = new androidx.activity.result.j();
        jVar.a = eVar;
        if (i >= 33 || (i >= 30 && SdkExtensions.getExtensionVersion(30) >= 2)) {
            pickImagesMaxLimit = MediaStore.getPickImagesMaxLimit();
        }
        jVar.b = pickImagesMaxLimit;
        jVar.c = defaultTab;
        Intrinsics.checkNotNullParameter(mediaType, "<set-?>");
        jVar.a = mediaType;
        jVar.b = pickImagesMaxLimit2;
        Intrinsics.checkNotNullParameter(defaultTab, "<set-?>");
        jVar.c = defaultTab;
        return jVar;
    }

    public static final String b(String str) throws UnsupportedEncodingException {
        Intrinsics.checkNotNullParameter(str, "<this>");
        try {
            String strDecode = URLDecoder.decode(str, "UTF-8");
            Intrinsics.checkNotNullExpressionValue(strDecode, "decode(...)");
            return strDecode;
        } catch (UnsupportedEncodingException e) {
            timber.log.c.a.f(e, AbstractC0147y.d("Trying to decode url: ", str), new Object[0]);
            return str;
        }
    }
}

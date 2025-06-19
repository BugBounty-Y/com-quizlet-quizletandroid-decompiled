package com.google.android.gms.internal.mlkit_vision_common;

import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Bundle;
import com.amazon.device.ads.DtbConstants;
import com.facebook.AccessToken;
import java.util.Arrays;
import java.util.Locale;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class A2 {
    public static final /* synthetic */ int a = 0;

    public static com.facebook.t a(String str, AccessToken accessToken, String str2) {
        String str3;
        Intrinsics.checkNotNullParameter("app_indexing", "requestType");
        if (str == null) {
            return null;
        }
        String str4 = com.facebook.t.j;
        String str5 = String.format(Locale.US, "%s/app_indexing", Arrays.copyOf(new Object[]{str2}, 1));
        Intrinsics.checkNotNullExpressionValue(str5, "format(locale, format, *args)");
        com.facebook.t tVarR = assistantMode.utils.studiableMetadata.b.R(accessToken, str5, null, null);
        Bundle bundle = tVarR.d;
        if (bundle == null) {
            bundle = new Bundle();
        }
        bundle.putString("tree", str);
        Context contextA = com.facebook.o.a();
        try {
            str3 = contextA.getPackageManager().getPackageInfo(contextA.getPackageName(), 0).versionName;
            Intrinsics.checkNotNullExpressionValue(str3, "{\n      val packageInfo …ageInfo.versionName\n    }");
        } catch (PackageManager.NameNotFoundException unused) {
            str3 = "";
        }
        bundle.putString("app_version", str3);
        bundle.putString("platform", DtbConstants.NATIVE_OS_NAME);
        bundle.putString("request_type", "app_indexing");
        bundle.putString("device_session_id", com.facebook.appevents.codeless.d.a());
        Intrinsics.checkNotNullParameter(bundle, "<set-?>");
        tVarR.d = bundle;
        tVarR.j(new com.facebook.r(2));
        return tVarR;
    }
}

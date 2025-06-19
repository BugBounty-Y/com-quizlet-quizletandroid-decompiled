package com.google.android.gms.internal.mlkit_vision_common;

import android.os.Bundle;
import android.util.Base64;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import com.comscore.streaming.ContentType;
import com.facebook.AccessToken;
import com.facebook.AuthenticationToken;
import com.facebook.FacebookException;
import com.quizlet.features.achievements.ui.composables.C4214a;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.Charsets;
import kotlin.text.StringsKt__StringsKt;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public abstract class J2 {
    public static final void a(String contentDescription, androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        String str;
        Intrinsics.checkNotNullParameter(contentDescription, "contentDescription");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1043040545);
        int i2 = (c0814p.f(contentDescription) ? 4 : 2) | i | 48;
        if ((i2 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
            str = contentDescription;
        } else {
            qVar = androidx.compose.ui.n.b;
            com.quizlet.themes.m.g.h();
            androidx.compose.ui.q qVarK = androidx.compose.foundation.layout.K0.k(qVar, com.quizlet.ui.resources.designsystem.generated.h.g);
            com.quizlet.themes.e.a(c0814p).a.getClass();
            str = contentDescription;
            androidx.compose.material3.D1.a(com.quizlet.ui.resources.icons.d.o(c0814p), str, qVarK, 0L, c0814p, (i2 << 3) & ContentType.LONG_FORM_ON_DEMAND, 8);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C4214a(str, qVar, i, 4);
        }
    }

    public static AccessToken b(Bundle bundle, String applicationId) {
        String string;
        com.facebook.g gVar = com.facebook.g.FACEBOOK_APPLICATION_SERVICE;
        Intrinsics.checkNotNullParameter(bundle, "bundle");
        Intrinsics.checkNotNullParameter(applicationId, "applicationId");
        Date dateN = com.facebook.internal.J.n(bundle, "com.facebook.platform.extra.EXPIRES_SECONDS_SINCE_EPOCH", new Date(0L));
        ArrayList<String> stringArrayList = bundle.getStringArrayList("com.facebook.platform.extra.PERMISSIONS");
        String string2 = bundle.getString("com.facebook.platform.extra.ACCESS_TOKEN");
        Date dateN2 = com.facebook.internal.J.n(bundle, "com.facebook.platform.extra.EXTRA_DATA_ACCESS_EXPIRATION_TIME", new Date(0L));
        if (string2 == null || string2.length() == 0 || (string = bundle.getString("com.facebook.platform.extra.USER_ID")) == null || string.length() == 0) {
            return null;
        }
        return new AccessToken(string2, applicationId, string, stringArrayList, null, null, gVar, dateN, new Date(), dateN2, bundle.getString("graph_domain"));
    }

    public static AccessToken c(Collection collection, Bundle bundle, com.facebook.g gVar, String applicationId) throws JSONException, NumberFormatException {
        ArrayList arrayListF;
        ArrayList arrayListF2;
        Intrinsics.checkNotNullParameter(bundle, "bundle");
        Intrinsics.checkNotNullParameter(applicationId, "applicationId");
        Date dateN = com.facebook.internal.J.n(bundle, "expires_in", new Date());
        String string = bundle.getString("access_token");
        if (string != null) {
            Date dateN2 = com.facebook.internal.J.n(bundle, "data_access_expiration_time", new Date(0L));
            String string2 = bundle.getString("granted_scopes");
            if (string2 != null && string2.length() > 0) {
                String[] strArr = (String[]) StringsKt__StringsKt.split$default(string2, new String[]{","}, false, 0, 6, null).toArray(new String[0]);
                collection = kotlin.collections.B.f(Arrays.copyOf(strArr, strArr.length));
            }
            String string3 = bundle.getString("denied_scopes");
            if (string3 == null || string3.length() <= 0) {
                arrayListF = null;
            } else {
                String[] strArr2 = (String[]) StringsKt__StringsKt.split$default(string3, new String[]{","}, false, 0, 6, null).toArray(new String[0]);
                arrayListF = kotlin.collections.B.f(Arrays.copyOf(strArr2, strArr2.length));
            }
            String string4 = bundle.getString("expired_scopes");
            if (string4 == null || string4.length() <= 0) {
                arrayListF2 = null;
            } else {
                String[] strArr3 = (String[]) StringsKt__StringsKt.split$default(string4, new String[]{","}, false, 0, 6, null).toArray(new String[0]);
                arrayListF2 = kotlin.collections.B.f(Arrays.copyOf(strArr3, strArr3.length));
            }
            if (!com.facebook.internal.J.D(string)) {
                String string5 = bundle.getString("graph_domain");
                String string6 = bundle.getString("signed_request");
                if (string6 == null || string6.length() == 0) {
                    throw new FacebookException("Authorization response does not contain the signed_request");
                }
                try {
                    String[] strArr4 = (String[]) StringsKt__StringsKt.split$default(string6, new String[]{"."}, false, 0, 6, null).toArray(new String[0]);
                    if (strArr4.length == 2) {
                        byte[] data = Base64.decode(strArr4[1], 0);
                        Intrinsics.checkNotNullExpressionValue(data, "data");
                        String string7 = new JSONObject(new String(data, Charsets.UTF_8)).getString("user_id");
                        Intrinsics.checkNotNullExpressionValue(string7, "jsonObject.getString(\"user_id\")");
                        return new AccessToken(string, applicationId, string7, collection, arrayListF, arrayListF2, gVar, dateN, new Date(), dateN2, string5);
                    }
                } catch (UnsupportedEncodingException | JSONException unused) {
                }
                throw new FacebookException("Failed to retrieve user_id from signed_request");
            }
        }
        return null;
    }

    public static AuthenticationToken d(Bundle bundle, String str) {
        Intrinsics.checkNotNullParameter(bundle, "bundle");
        String string = bundle.getString("id_token");
        if (string == null || string.length() == 0 || str == null || str.length() == 0) {
            return null;
        }
        try {
            return new AuthenticationToken(string, str);
        } catch (Exception e) {
            throw new FacebookException(e.getMessage(), e);
        }
    }
}

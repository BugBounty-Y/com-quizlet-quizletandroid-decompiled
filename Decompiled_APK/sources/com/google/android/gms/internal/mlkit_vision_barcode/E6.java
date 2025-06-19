package com.google.android.gms.internal.mlkit_vision_barcode;

import android.app.Activity;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import androidx.credentials.exceptions.GetCredentialCustomException;
import androidx.credentials.exceptions.GetCredentialException;
import androidx.credentials.exceptions.publickeycredential.GetPublicKeyCredentialDomException;
import androidx.credentials.internal.FrameworkClassParsingException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TimeZone;
import kotlin.NoWhenBranchMatchedException;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt__StringsKt;

/* loaded from: classes2.dex */
public abstract class E6 {
    public static final /* synthetic */ int a = 0;

    public static final void a(String str, Object obj, Map map) {
        Intrinsics.checkNotNullParameter(map, "map");
        if (obj == null || str.length() == 0) {
            return;
        }
        map.put(str, obj);
    }

    public static GetCredentialException b(String type, String str) throws FrameworkClassParsingException {
        Exception excA;
        Intrinsics.checkNotNullParameter(type, "type");
        try {
            GetPublicKeyCredentialDomException getPublicKeyCredentialDomException = new GetPublicKeyCredentialDomException(new androidx.credentials.exceptions.domerrors.a(26), null);
            if (Intrinsics.b(type, "androidx.credentials.TYPE_GET_PUBLIC_KEY_CREDENTIAL_DOM_EXCEPTION/androidx.credentials.TYPE_ABORT_ERROR")) {
                excA = D6.a(new androidx.credentials.exceptions.domerrors.a(0), str, getPublicKeyCredentialDomException);
            } else if (Intrinsics.b(type, "androidx.credentials.TYPE_GET_PUBLIC_KEY_CREDENTIAL_DOM_EXCEPTION/androidx.credentials.TYPE_CONSTRAINT_ERROR")) {
                excA = D6.a(new androidx.credentials.exceptions.domerrors.a(1), str, getPublicKeyCredentialDomException);
            } else if (Intrinsics.b(type, "androidx.credentials.TYPE_GET_PUBLIC_KEY_CREDENTIAL_DOM_EXCEPTION/androidx.credentials.TYPE_DATA_CLONE_ERROR")) {
                excA = D6.a(new androidx.credentials.exceptions.domerrors.a("androidx.credentials.TYPE_DATA_CLONE_ERROR"), str, getPublicKeyCredentialDomException);
            } else if (Intrinsics.b(type, "androidx.credentials.TYPE_GET_PUBLIC_KEY_CREDENTIAL_DOM_EXCEPTION/androidx.credentials.TYPE_DATA_ERROR")) {
                excA = D6.a(new androidx.credentials.exceptions.domerrors.a(3), str, getPublicKeyCredentialDomException);
            } else if (Intrinsics.b(type, "androidx.credentials.TYPE_GET_PUBLIC_KEY_CREDENTIAL_DOM_EXCEPTION/androidx.credentials.TYPE_ENCODING_ERROR")) {
                excA = D6.a(new androidx.credentials.exceptions.domerrors.a(4), str, getPublicKeyCredentialDomException);
            } else if (Intrinsics.b(type, "androidx.credentials.TYPE_GET_PUBLIC_KEY_CREDENTIAL_DOM_EXCEPTION/androidx.credentials.TYPE_HIERARCHY_REQUEST_ERROR")) {
                excA = D6.a(new androidx.credentials.exceptions.domerrors.a("androidx.credentials.TYPE_HIERARCHY_REQUEST_ERROR"), str, getPublicKeyCredentialDomException);
            } else if (Intrinsics.b(type, "androidx.credentials.TYPE_GET_PUBLIC_KEY_CREDENTIAL_DOM_EXCEPTION/androidx.credentials.TYPE_IN_USE_ATTRIBUTE_ERROR")) {
                excA = D6.a(new androidx.credentials.exceptions.domerrors.a("androidx.credentials.TYPE_IN_USE_ATTRIBUTE_ERROR"), str, getPublicKeyCredentialDomException);
            } else if (Intrinsics.b(type, "androidx.credentials.TYPE_GET_PUBLIC_KEY_CREDENTIAL_DOM_EXCEPTION/androidx.credentials.TYPE_INVALID_CHARACTER_ERROR")) {
                excA = D6.a(new androidx.credentials.exceptions.domerrors.a("androidx.credentials.TYPE_INVALID_CHARACTER_ERROR"), str, getPublicKeyCredentialDomException);
            } else if (Intrinsics.b(type, "androidx.credentials.TYPE_GET_PUBLIC_KEY_CREDENTIAL_DOM_EXCEPTION/androidx.credentials.TYPE_INVALID_MODIFICATION_ERROR")) {
                excA = D6.a(new androidx.credentials.exceptions.domerrors.a("androidx.credentials.TYPE_INVALID_MODIFICATION_ERROR"), str, getPublicKeyCredentialDomException);
            } else if (Intrinsics.b(type, "androidx.credentials.TYPE_GET_PUBLIC_KEY_CREDENTIAL_DOM_EXCEPTION/androidx.credentials.TYPE_INVALID_NODE_TYPE_ERROR")) {
                excA = D6.a(new androidx.credentials.exceptions.domerrors.a("androidx.credentials.TYPE_INVALID_NODE_TYPE_ERROR"), str, getPublicKeyCredentialDomException);
            } else if (Intrinsics.b(type, "androidx.credentials.TYPE_GET_PUBLIC_KEY_CREDENTIAL_DOM_EXCEPTION/androidx.credentials.TYPE_INVALID_STATE_ERROR")) {
                excA = D6.a(new androidx.credentials.exceptions.domerrors.a(10), str, getPublicKeyCredentialDomException);
            } else if (Intrinsics.b(type, "androidx.credentials.TYPE_GET_PUBLIC_KEY_CREDENTIAL_DOM_EXCEPTION/androidx.credentials.TYPE_NAMESPACE_ERROR")) {
                excA = D6.a(new androidx.credentials.exceptions.domerrors.a("androidx.credentials.TYPE_NAMESPACE_ERROR"), str, getPublicKeyCredentialDomException);
            } else if (Intrinsics.b(type, "androidx.credentials.TYPE_GET_PUBLIC_KEY_CREDENTIAL_DOM_EXCEPTION/androidx.credentials.TYPE_NETWORK_ERROR")) {
                excA = D6.a(new androidx.credentials.exceptions.domerrors.a(12), str, getPublicKeyCredentialDomException);
            } else if (Intrinsics.b(type, "androidx.credentials.TYPE_GET_PUBLIC_KEY_CREDENTIAL_DOM_EXCEPTION/androidx.credentials.TYPE_NO_MODIFICATION_ALLOWED_ERROR")) {
                excA = D6.a(new androidx.credentials.exceptions.domerrors.a("androidx.credentials.TYPE_NO_MODIFICATION_ALLOWED_ERROR"), str, getPublicKeyCredentialDomException);
            } else if (Intrinsics.b(type, "androidx.credentials.TYPE_GET_PUBLIC_KEY_CREDENTIAL_DOM_EXCEPTION/androidx.credentials.TYPE_NOT_ALLOWED_ERROR")) {
                excA = D6.a(new androidx.credentials.exceptions.domerrors.a(14), str, getPublicKeyCredentialDomException);
            } else if (Intrinsics.b(type, "androidx.credentials.TYPE_GET_PUBLIC_KEY_CREDENTIAL_DOM_EXCEPTION/androidx.credentials.TYPE_NOT_FOUND_ERROR")) {
                excA = D6.a(new androidx.credentials.exceptions.domerrors.a("androidx.credentials.TYPE_NOT_FOUND_ERROR"), str, getPublicKeyCredentialDomException);
            } else if (Intrinsics.b(type, "androidx.credentials.TYPE_GET_PUBLIC_KEY_CREDENTIAL_DOM_EXCEPTION/androidx.credentials.TYPE_NOT_READABLE_ERROR")) {
                excA = D6.a(new androidx.credentials.exceptions.domerrors.a(16), str, getPublicKeyCredentialDomException);
            } else if (Intrinsics.b(type, "androidx.credentials.TYPE_GET_PUBLIC_KEY_CREDENTIAL_DOM_EXCEPTION/androidx.credentials.TYPE_NOT_SUPPORTED_ERROR")) {
                excA = D6.a(new androidx.credentials.exceptions.domerrors.a(17), str, getPublicKeyCredentialDomException);
            } else if (Intrinsics.b(type, "androidx.credentials.TYPE_GET_PUBLIC_KEY_CREDENTIAL_DOM_EXCEPTION/androidx.credentials.TYPE_OPERATION_ERROR")) {
                excA = D6.a(new androidx.credentials.exceptions.domerrors.a("androidx.credentials.TYPE_OPERATION_ERROR"), str, getPublicKeyCredentialDomException);
            } else if (Intrinsics.b(type, "androidx.credentials.TYPE_GET_PUBLIC_KEY_CREDENTIAL_DOM_EXCEPTION/androidx.credentials.TYPE_OPT_OUT_ERROR")) {
                excA = D6.a(new androidx.credentials.exceptions.domerrors.a("androidx.credentials.TYPE_OPT_OUT_ERROR"), str, getPublicKeyCredentialDomException);
            } else if (Intrinsics.b(type, "androidx.credentials.TYPE_GET_PUBLIC_KEY_CREDENTIAL_DOM_EXCEPTION/androidx.credentials.TYPE_QUOTA_EXCEEDED_ERROR")) {
                excA = D6.a(new androidx.credentials.exceptions.domerrors.a("androidx.credentials.TYPE_QUOTA_EXCEEDED_ERROR"), str, getPublicKeyCredentialDomException);
            } else if (Intrinsics.b(type, "androidx.credentials.TYPE_GET_PUBLIC_KEY_CREDENTIAL_DOM_EXCEPTION/androidx.credentials.TYPE_READ_ONLY_ERROR")) {
                excA = D6.a(new androidx.credentials.exceptions.domerrors.a("androidx.credentials.TYPE_READ_ONLY_ERROR"), str, getPublicKeyCredentialDomException);
            } else if (Intrinsics.b(type, "androidx.credentials.TYPE_GET_PUBLIC_KEY_CREDENTIAL_DOM_EXCEPTION/androidx.credentials.TYPE_SECURITY_ERROR")) {
                excA = D6.a(new androidx.credentials.exceptions.domerrors.a(22), str, getPublicKeyCredentialDomException);
            } else if (Intrinsics.b(type, "androidx.credentials.TYPE_GET_PUBLIC_KEY_CREDENTIAL_DOM_EXCEPTION/androidx.credentials.TYPE_SYNTAX_ERROR")) {
                excA = D6.a(new androidx.credentials.exceptions.domerrors.a("androidx.credentials.TYPE_SYNTAX_ERROR"), str, getPublicKeyCredentialDomException);
            } else if (Intrinsics.b(type, "androidx.credentials.TYPE_GET_PUBLIC_KEY_CREDENTIAL_DOM_EXCEPTION/androidx.credentials.TYPE_TIMEOUT_ERROR")) {
                excA = D6.a(new androidx.credentials.exceptions.domerrors.a(24), str, getPublicKeyCredentialDomException);
            } else if (Intrinsics.b(type, "androidx.credentials.TYPE_GET_PUBLIC_KEY_CREDENTIAL_DOM_EXCEPTION/androidx.credentials.TYPE_TRANSACTION_INACTIVE_ERROR")) {
                excA = D6.a(new androidx.credentials.exceptions.domerrors.a("androidx.credentials.TYPE_TRANSACTION_INACTIVE_ERROR"), str, getPublicKeyCredentialDomException);
            } else if (Intrinsics.b(type, "androidx.credentials.TYPE_GET_PUBLIC_KEY_CREDENTIAL_DOM_EXCEPTION/androidx.credentials.TYPE_UNKNOWN_ERROR")) {
                excA = D6.a(new androidx.credentials.exceptions.domerrors.a(26), str, getPublicKeyCredentialDomException);
            } else if (Intrinsics.b(type, "androidx.credentials.TYPE_GET_PUBLIC_KEY_CREDENTIAL_DOM_EXCEPTION/androidx.credentials.TYPE_VERSION_ERROR")) {
                excA = D6.a(new androidx.credentials.exceptions.domerrors.a("androidx.credentials.TYPE_VERSION_ERROR"), str, getPublicKeyCredentialDomException);
            } else {
                if (!Intrinsics.b(type, "androidx.credentials.TYPE_GET_PUBLIC_KEY_CREDENTIAL_DOM_EXCEPTION/androidx.credentials.TYPE_WRONG_DOCUMENT_ERROR")) {
                    throw new FrameworkClassParsingException();
                }
                excA = D6.a(new androidx.credentials.exceptions.domerrors.a("androidx.credentials.TYPE_WRONG_DOCUMENT_ERROR"), str, getPublicKeyCredentialDomException);
            }
            return (GetCredentialException) excA;
        } catch (FrameworkClassParsingException unused) {
            return new GetCredentialCustomException(str, type);
        }
    }

    public static final String c(long j) {
        Date date = new Date(j);
        Intrinsics.checkNotNullParameter(date, "date");
        SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", new Locale("en"));
        simpleDateFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
        String str = simpleDateFormat.format(date);
        Intrinsics.checkNotNullExpressionValue(str, "dateFormat.format(date)");
        return str;
    }

    public static final boolean d(Activity context) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullExpressionValue("E6", "TAG");
        boolean z = false;
        com.snowplowanalytics.core.tracker.e.e("E6", "Checking tracker internet connectivity.", new Object[0]);
        Object systemService = context.getSystemService("connectivity");
        NetworkInfo activeNetworkInfo = null;
        ConnectivityManager connectivityManager = systemService instanceof ConnectivityManager ? (ConnectivityManager) systemService : null;
        if (connectivityManager != null) {
            try {
                activeNetworkInfo = connectivityManager.getActiveNetworkInfo();
            } catch (SecurityException e) {
                Intrinsics.checkNotNullExpressionValue("E6", "TAG");
                com.snowplowanalytics.core.tracker.e.b("E6", "Security exception checking connection: %s", e.toString());
                return true;
            }
        }
        if (activeNetworkInfo != null && activeNetworkInfo.isConnected()) {
            z = true;
        }
        Intrinsics.checkNotNullExpressionValue("E6", "TAG");
        com.snowplowanalytics.core.tracker.e.a("E6", "Tracker connection online: %s", Boolean.valueOf(z));
        return z;
    }

    public static final boolean e(HashMap map, String... keys) {
        Intrinsics.checkNotNullParameter(map, "map");
        Intrinsics.checkNotNullParameter(keys, "keys");
        for (String str : keys) {
            if (!map.containsKey(str)) {
                return false;
            }
        }
        return true;
    }

    public static final assistantMode.enums.m f(com.quizlet.features.infra.models.flashcards.h hVar, com.quizlet.features.infra.models.flashcards.d settings) {
        Intrinsics.checkNotNullParameter(settings, "settings");
        int i = hVar == null ? -1 : com.quizlet.features.infra.models.flashcards.i.a[hVar.ordinal()];
        if (i != -1 && i != 1) {
            if (i == 2) {
                return settings.b;
            }
            throw new NoWhenBranchMatchedException();
        }
        return settings.a;
    }

    public static String g(String url) {
        Intrinsics.checkNotNullParameter(url, "url");
        List listSplit$default = StringsKt__StringsKt.split$default(url, new String[]{"://"}, false, 0, 6, null);
        return listSplit$default.size() > 1 ? CollectionsKt.S(CollectionsKt.c0(kotlin.collections.A.b(kotlin.text.I.C(16, (String) CollectionsKt.L(listSplit$default))), CollectionsKt.H(1, listSplit$default)), "://", null, null, null, 62) : url;
    }
}

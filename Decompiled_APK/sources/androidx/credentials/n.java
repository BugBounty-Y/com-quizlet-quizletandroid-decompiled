package androidx.credentials;

import android.os.Bundle;
import androidx.appcompat.app.y;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final class n extends y {
    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public n(int i, Bundle bundle, String jsonString) {
        super(bundle, "android.credentials.TYPE_PASSWORD_CREDENTIAL");
        switch (i) {
            case 2:
                super(bundle, "androidx.credentials.TYPE_PUBLIC_KEY_CREDENTIAL");
                Intrinsics.checkNotNullParameter(jsonString, "jsonString");
                if (jsonString.length() != 0) {
                    try {
                        new JSONObject(jsonString);
                        return;
                    } catch (Exception unused) {
                    }
                }
                throw new IllegalArgumentException("authenticationResponseJson must not be empty, and must be a valid JSON");
            default:
                if (jsonString.length() <= 0) {
                    throw new IllegalArgumentException("password should not be empty");
                }
                return;
        }
    }
}

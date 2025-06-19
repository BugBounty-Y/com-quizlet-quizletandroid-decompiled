package com.perimeterx.mobile_sdk.local_data;

import android.app.Application;
import android.content.SharedPreferences;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3744v4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.F4;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.locks.ReentrantLock;
import kotlin.Pair;
import kotlin.collections.V;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.E;
import kotlinx.coroutines.O;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class a implements b {
    public final Application a;
    public final HashMap b;
    public final ReentrantLock c;

    public a(Application application) {
        Intrinsics.checkNotNullParameter(application, "application");
        this.a = application;
        this.b = new HashMap();
        this.c = new ReentrantLock();
    }

    @Override // com.perimeterx.mobile_sdk.local_data.b
    public final String a(x key, String appId) throws JSONException {
        Intrinsics.checkNotNullParameter(key, "key");
        Intrinsics.checkNotNullParameter(appId, "appId");
        SharedPreferences sharedPreferencesG = g(appId);
        if (sharedPreferencesG != null) {
            return sharedPreferencesG.getString(key.a(), null);
        }
        return null;
    }

    @Override // com.perimeterx.mobile_sdk.local_data.b
    public final void b(int i, x key, String appId) throws JSONException {
        Intrinsics.checkNotNullParameter(key, "key");
        Intrinsics.checkNotNullParameter(appId, "appId");
        SharedPreferences sharedPreferencesG = g(appId);
        if (sharedPreferencesG != null) {
            SharedPreferences.Editor editorEdit = sharedPreferencesG.edit();
            editorEdit.putInt(key.a(), i);
            editorEdit.apply();
        }
    }

    @Override // com.perimeterx.mobile_sdk.local_data.b
    public final void c(String value, x key, String appId) throws JSONException {
        Intrinsics.checkNotNullParameter(value, "value");
        Intrinsics.checkNotNullParameter(key, "key");
        Intrinsics.checkNotNullParameter(appId, "appId");
        SharedPreferences sharedPreferencesG = g(appId);
        if (sharedPreferencesG != null) {
            SharedPreferences.Editor editorEdit = sharedPreferencesG.edit();
            editorEdit.putString(key.a(), value);
            editorEdit.apply();
        }
    }

    @Override // com.perimeterx.mobile_sdk.local_data.b
    public final void d(boolean z, x key, String appId) throws JSONException {
        Intrinsics.checkNotNullParameter(key, "key");
        Intrinsics.checkNotNullParameter(appId, "appId");
        SharedPreferences sharedPreferencesG = g(appId);
        if (sharedPreferencesG != null) {
            SharedPreferences.Editor editorEdit = sharedPreferencesG.edit();
            editorEdit.putBoolean(key.a(), z);
            editorEdit.apply();
        }
    }

    @Override // com.perimeterx.mobile_sdk.local_data.b
    public final Boolean e(x key, String appId) throws JSONException {
        Intrinsics.checkNotNullParameter(key, "key");
        Intrinsics.checkNotNullParameter(appId, "appId");
        SharedPreferences sharedPreferencesG = g(appId);
        if (sharedPreferencesG != null) {
            return Boolean.valueOf(sharedPreferencesG.getBoolean(key.a(), false));
        }
        return null;
    }

    @Override // com.perimeterx.mobile_sdk.local_data.b
    public final Integer f(x key, String appId) throws JSONException {
        Intrinsics.checkNotNullParameter(key, "key");
        Intrinsics.checkNotNullParameter(appId, "appId");
        SharedPreferences sharedPreferencesG = g(appId);
        if (sharedPreferencesG != null) {
            return Integer.valueOf(sharedPreferencesG.getInt(key.a(), 0));
        }
        return null;
    }

    public final SharedPreferences g(String appId) throws JSONException {
        ReentrantLock reentrantLock = this.c;
        reentrantLock.lock();
        HashMap map = this.b;
        SharedPreferences sharedPreferences = (SharedPreferences) map.get(appId);
        if (sharedPreferences != null) {
            reentrantLock.unlock();
            return sharedPreferences;
        }
        String str = com.perimeterx.mobile_sdk.configurations.i.a;
        Intrinsics.checkNotNullParameter(appId, "appId");
        SharedPreferences sharedPreferences2 = this.a.getSharedPreferences(com.perimeterx.mobile_sdk.configurations.i.a("com.perimeterx.mobile_sdk.%@", appId), 0);
        if (sharedPreferences2 != null) {
            map.put(appId, sharedPreferences2);
            reentrantLock.unlock();
            return sharedPreferences2;
        }
        reentrantLock.unlock();
        HashMap userInfo = V.e(new Pair(com.perimeterx.mobile_sdk.logger.c.a.a(), "failed to create storage"));
        Intrinsics.checkNotNullParameter(userInfo, "userInfo");
        String str2 = F4.a;
        if (str2 != null) {
            com.perimeterx.mobile_sdk.session.l lVar = com.perimeterx.mobile_sdk.session.l.a;
            Application application = com.perimeterx.mobile_sdk.session.l.b;
            if (application != null) {
                JSONObject jSONObject = new JSONObject();
                for (Map.Entry entry : userInfo.entrySet()) {
                    jSONObject.putOpt((String) entry.getKey(), (String) entry.getValue());
                }
                E.A(E.c(O.a), null, null, new com.perimeterx.mobile_sdk.logger.a(str2, jSONObject, new com.quizlet.data.interactor.set.c((com.perimeterx.mobile_sdk.session.m) null, new androidx.camera.camera2.internal.compat.workaround.a()).b(application), AbstractC3744v4.a(application), null), 3);
            }
        }
        return null;
    }

    @Override // com.perimeterx.mobile_sdk.local_data.b
    public final void a(String appId) throws JSONException {
        SharedPreferences.Editor editorEdit;
        SharedPreferences.Editor editorClear;
        Intrinsics.checkNotNullParameter(appId, "appId");
        SharedPreferences sharedPreferencesG = g(appId);
        if (sharedPreferencesG == null || (editorEdit = sharedPreferencesG.edit()) == null || (editorClear = editorEdit.clear()) == null) {
            return;
        }
        editorClear.apply();
    }
}

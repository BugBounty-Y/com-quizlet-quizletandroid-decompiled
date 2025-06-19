package com.pubmatic.sdk.webrendering.mraid;

import android.webkit.JavascriptInterface;
import androidx.annotation.Keep;
import androidx.annotation.NonNull;
import androidx.camera.camera2.internal.AbstractC0147y;
import com.pubmatic.sdk.common.log.POBLog;
import com.pubmatic.sdk.common.models.h;
import com.quizlet.db.data.models.persisted.fields.DBUserFields;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import org.json.JSONException;
import org.json.JSONObject;

@Keep
/* loaded from: classes2.dex */
public class POBMraidBridge {
    private static final String JS_CLASS = "mraidService";
    private static final String MRAID_MAPPING = "nativeBridge";
    private static final String TAG = "POBMraidBridge";

    @NonNull
    private final Map<String, n> commandHandlingMap;
    private t mraidBridgeListener;

    @NonNull
    private j mraidState = j.LOADING;

    @NonNull
    private final Map<b, String> propertyMap;

    @NonNull
    protected final com.pubmatic.sdk.common.view.c webView;

    public class a implements Runnable {
        final /* synthetic */ String a;

        public a(String str) {
            this.a = str;
        }

        @Override // java.lang.Runnable
        public void run() {
            POBMraidBridge.this.acknowledgeMraidCommand();
            POBLog.debug(POBMraidBridge.TAG, "Received MRAID event : %s", this.a);
            try {
                POBMraidBridge.this.invokeMraidCommands(new JSONObject(this.a));
            } catch (JSONException e) {
                POBLog.error(POBMraidBridge.TAG, "Failed to parse MRAID event. Error : %s", e.getLocalizedMessage());
                POBMraidBridge.this.notifyError("Not supported", this.a);
            }
        }
    }

    public enum b {
        CURRENT_POSITION,
        DEFAULT_POSITION,
        SCREEN_SIZE,
        MAX_SIZE,
        STATE,
        VIEWABLE
    }

    public POBMraidBridge(@NonNull com.pubmatic.sdk.common.view.c cVar) {
        this.webView = cVar;
        cVar.addJavascriptInterface(this, MRAID_MAPPING);
        this.propertyMap = new HashMap(5);
        this.commandHandlingMap = new HashMap(4);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void acknowledgeMraidCommand() {
        injectProperties("mraidService.nativeCallComplete();");
    }

    private void injectProperties(String str) {
        POBLog.debug(TAG, "Injecting JS property : %s", str);
        this.webView.loadUrl("javascript:" + str);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void invokeMraidCommands(@NonNull JSONObject jSONObject) {
        com.pubmatic.sdk.common.h hVar;
        String strOptString = jSONObject.optString("name");
        n nVar = this.commandHandlingMap.get(strOptString);
        if (nVar == null) {
            hVar = new com.pubmatic.sdk.common.h(1009, "Not supported");
        } else if (this.mraidBridgeListener == null || nVar.b()) {
            t tVar = this.mraidBridgeListener;
            hVar = (tVar == null || !tVar.isUserInteracted(true)) ? new com.pubmatic.sdk.common.h(1009, "Illegal state of command execution without user interaction") : nVar.a(jSONObject, this.mraidBridgeListener, true);
        } else {
            hVar = nVar.a(jSONObject, this.mraidBridgeListener, this.mraidBridgeListener.isUserInteracted(false));
        }
        if (hVar != null) {
            notifyError(hVar.getErrorMessage(), strOptString);
        }
    }

    private boolean isPropertyUpdated(b bVar, String str) {
        String str2 = this.propertyMap.get(bVar);
        if (str2 != null && str2.equals(str)) {
            return false;
        }
        this.propertyMap.put(bVar, str);
        return true;
    }

    public void addCommandHandler(@NonNull n nVar) {
        this.commandHandlingMap.put(nVar.a(), nVar);
    }

    @JavascriptInterface
    public void error(String str) {
        POBLog.error(TAG, "Error message from JS :%s", str);
    }

    @NonNull
    public j getMraidState() {
        return this.mraidState;
    }

    @JavascriptInterface
    public void log(String str) {
        POBLog.debug(TAG, "Received MRAID log :%s", str);
    }

    @JavascriptInterface
    public void nativeCall(String str) {
        com.pubmatic.sdk.common.utility.o.runOnMainThread(new a(str));
    }

    public void notifyError(String str, String str2) {
        POBLog.debug(TAG, "JS called MRAID event without user interaction. Event : %s", str2);
        Locale.getDefault();
        injectProperties(JS_CLASS.concat(".fireErrorEvent('" + str + "', '" + str2 + "');"));
    }

    public void resetPropertyMap() {
        this.propertyMap.clear();
    }

    public void setAudioVolumePercentage(Double d) {
        String str;
        if (d != null) {
            str = String.format(Locale.getDefault(), ".fireEvent('audioVolumeChange', %.2f);", d);
        } else {
            Locale.getDefault();
            str = ".fireEvent('audioVolumeChange', null);";
        }
        injectProperties(JS_CLASS.concat(str));
    }

    public boolean setCurrentPosition(int i, int i2, int i3, int i4) throws JSONException {
        JSONObject rectJson = C4074c.getRectJson(i, i2, i3, i4);
        if (!isPropertyUpdated(b.CURRENT_POSITION, rectJson.toString())) {
            return false;
        }
        injectProperties(JS_CLASS.concat(String.format(Locale.getDefault(), ".setCurrentPosition(%s);", rectJson)));
        return true;
    }

    public void setDefaultPosition(int i, int i2, int i3, int i4) throws JSONException {
        JSONObject rectJson = C4074c.getRectJson(i, i2, i3, i4);
        if (isPropertyUpdated(b.DEFAULT_POSITION, rectJson.toString())) {
            injectProperties(JS_CLASS.concat(String.format(Locale.getDefault(), ".setDefaultPosition(%s);", rectJson)));
        }
    }

    public void setLocation(com.pubmatic.sdk.common.models.h hVar) throws JSONException {
        String str;
        if (hVar != null) {
            try {
                JSONObject jSONObject = new JSONObject();
                jSONObject.put("lat", hVar.getLatitude());
                jSONObject.put("lon", hVar.getLongitude());
                h.a source = hVar.getSource();
                if (source != null) {
                    jSONObject.put(DBUserFields.Names.USER_UPGRADE_TYPE, String.valueOf(source.getValue()));
                }
                str = String.format(Locale.getDefault(), ".setLocation(%s);", jSONObject);
            } catch (Exception unused) {
                POBLog.error(TAG, "Not able to inject setLocation property!", new Object[0]);
                str = null;
            }
        } else {
            Locale.getDefault();
            str = ".setLocation({});";
        }
        injectProperties(AbstractC0147y.d(JS_CLASS, str));
    }

    public boolean setMaxSize(int i, int i2) throws JSONException {
        JSONObject heightWidthJson = C4074c.getHeightWidthJson(i, i2);
        if (!isPropertyUpdated(b.MAX_SIZE, heightWidthJson.toString())) {
            return false;
        }
        injectProperties(JS_CLASS.concat(String.format(Locale.getDefault(), ".setMaxSize(%s);", heightWidthJson)));
        return true;
    }

    public void setMraidBridgeListener(t tVar) {
        this.mraidBridgeListener = tVar;
    }

    public void setMraidState(@NonNull j jVar) {
        this.mraidState = jVar;
    }

    public void setPlacementType(@NonNull String str) {
        Locale.getDefault();
        injectProperties(JS_CLASS.concat(".setPlacementType('" + str + "');"));
    }

    public void setScreenSize(int i, int i2) throws JSONException {
        JSONObject heightWidthJson = C4074c.getHeightWidthJson(i, i2);
        if (isPropertyUpdated(b.SCREEN_SIZE, heightWidthJson.toString())) {
            injectProperties(JS_CLASS.concat(String.format(Locale.getDefault(), ".setScreenSize(%s);", heightWidthJson)));
        }
    }

    public void setSizeChange(int i, int i2) {
        injectProperties(JS_CLASS.concat(String.format(Locale.getDefault(), ".fireEvent('%s', %d, %d);", i.SIZE_CHANGE.a(), Integer.valueOf(i), Integer.valueOf(i2))));
    }

    public void setSupportedFeatures(boolean z, boolean z2, boolean z3, boolean z4, boolean z5, boolean z6, boolean z7) throws JSONException {
        JSONObject jSONObject = new JSONObject();
        try {
            jSONObject.put("sms", z);
            jSONObject.put("tel", z2);
            jSONObject.put("calendar", z3);
            jSONObject.put("storePicture", z4);
            jSONObject.put("inlineVideo", z5);
            jSONObject.put("location", z6);
            jSONObject.put("vpaid", z7);
            injectProperties(JS_CLASS.concat(String.format(Locale.getDefault(), ".setSupports(%s);", jSONObject)));
        } catch (JSONException unused) {
            POBLog.error(TAG, "Not able to inject setSupports property!", new Object[0]);
        }
    }

    public void updateEvent(@NonNull i iVar) {
        Locale.getDefault();
        injectProperties(JS_CLASS.concat(".fireEvent('" + iVar.a() + "');"));
    }

    public void updateExposureChangeData(Float f, JSONObject jSONObject) {
        if (f == null || jSONObject == null) {
            return;
        }
        injectProperties(JS_CLASS.concat(String.format(Locale.getDefault(), ".fireEvent('exposureChange', %.1f, %s, null);", f, jSONObject)));
    }

    public void updateMraidState(@NonNull j jVar) {
        if (isPropertyUpdated(b.STATE, jVar.a())) {
            Locale.getDefault();
            injectProperties(JS_CLASS.concat(".setState('" + jVar.a() + "');"));
        }
    }

    public void updateViewable(boolean z) {
        if (isPropertyUpdated(b.VIEWABLE, String.valueOf(z))) {
            Locale.getDefault();
            injectProperties(JS_CLASS.concat(".setViewable(" + z + ");"));
        }
    }
}

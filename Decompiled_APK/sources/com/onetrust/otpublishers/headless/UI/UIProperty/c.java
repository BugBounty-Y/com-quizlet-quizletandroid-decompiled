package com.onetrust.otpublishers.headless.UI.UIProperty;

import android.content.Context;
import androidx.annotation.NonNull;
import androidx.compose.runtime.internal.j;
import androidx.constraintlayout.motion.widget.n;
import androidx.navigation.internal.m;
import androidx.room.s;
import com.google.android.gms.cloudmessaging.k;
import com.onetrust.otpublishers.headless.Public.Keys.OTUXParamsKeys;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class c {
    public final JSONObject a;

    public c(@NonNull Context context) {
        this.a = new JSONObject();
        String string = new com.onetrust.otpublishers.headless.Internal.Preferences.b(context).b().getString("OTT_UX_PARAMS_JSON", "");
        if (com.onetrust.otpublishers.headless.Internal.a.j(string)) {
            return;
        }
        this.a = new JSONObject(string);
    }

    public static n a(JSONObject jSONObject) {
        n nVar = new n();
        nVar.d = d(jSONObject);
        if (jSONObject.has(OTUXParamsKeys.OT_UX_BACKGROUND_COLOR)) {
            nVar.e = jSONObject.getString(OTUXParamsKeys.OT_UX_BACKGROUND_COLOR);
        }
        if (jSONObject.has(OTUXParamsKeys.OT_UX_TEXT_COLOR)) {
            nVar.f = jSONObject.getString(OTUXParamsKeys.OT_UX_TEXT_COLOR);
        }
        if (jSONObject.has(OTUXParamsKeys.OT_UX_BORDER_COLOR)) {
            nVar.g = jSONObject.getString(OTUXParamsKeys.OT_UX_BORDER_COLOR);
        }
        if (jSONObject.has(OTUXParamsKeys.OT_UX_BORDER_WIDTH)) {
            nVar.h = jSONObject.getString(OTUXParamsKeys.OT_UX_BORDER_WIDTH);
        }
        if (jSONObject.has(OTUXParamsKeys.OT_UX_BORDER_RADIUS)) {
            nVar.i = jSONObject.getString(OTUXParamsKeys.OT_UX_BORDER_RADIUS);
        }
        return nVar;
    }

    public static k d(JSONObject jSONObject) {
        k kVar = new k(9);
        if (jSONObject.has(OTUXParamsKeys.OT_UX_FONT_NAME)) {
            kVar.c = jSONObject.getString(OTUXParamsKeys.OT_UX_FONT_NAME);
        }
        if (jSONObject.has(OTUXParamsKeys.OT_UX_FONT_SIZE)) {
            kVar.d = jSONObject.getString(OTUXParamsKeys.OT_UX_FONT_SIZE);
        }
        if (jSONObject.has(OTUXParamsKeys.OT_UX_FONT_TEXT_STYLE)) {
            kVar.b = jSONObject.getInt(OTUXParamsKeys.OT_UX_FONT_TEXT_STYLE);
        }
        if (jSONObject.has(OTUXParamsKeys.OT_UX_FONT_TYPE_FACE_KEY)) {
            kVar.e = jSONObject.getString(OTUXParamsKeys.OT_UX_FONT_TYPE_FACE_KEY);
        }
        return kVar;
    }

    public static com.quizlet.data.repository.user.e e(JSONObject jSONObject) {
        com.quizlet.data.repository.user.e eVar = new com.quizlet.data.repository.user.e();
        eVar.b = g(jSONObject);
        return eVar;
    }

    public static j f(JSONObject jSONObject) {
        j jVar = new j();
        if (jSONObject.has(OTUXParamsKeys.OT_UX_BACKGROUND_COLOR)) {
            jVar.a = jSONObject.getString(OTUXParamsKeys.OT_UX_BACKGROUND_COLOR);
        }
        if (jSONObject.has(OTUXParamsKeys.OT_UX_TEXT_COLOR)) {
            jVar.b = jSONObject.getString(OTUXParamsKeys.OT_UX_TEXT_COLOR);
        }
        if (jSONObject.has(OTUXParamsKeys.OT_UX_PLACEHOLDER_TEXT_COLOR)) {
            jVar.c = jSONObject.getString(OTUXParamsKeys.OT_UX_PLACEHOLDER_TEXT_COLOR);
        }
        if (jSONObject.has(OTUXParamsKeys.OT_UX_ICON_COLOR)) {
            jVar.d = jSONObject.getString(OTUXParamsKeys.OT_UX_ICON_COLOR);
        }
        if (jSONObject.has(OTUXParamsKeys.OT_UX_CLEAR_BUTTON_COLOR)) {
            jVar.f = jSONObject.getString(OTUXParamsKeys.OT_UX_CLEAR_BUTTON_COLOR);
        }
        if (jSONObject.has(OTUXParamsKeys.OT_UX_BORDER_COLOR)) {
            jVar.e = jSONObject.getString(OTUXParamsKeys.OT_UX_BORDER_COLOR);
        }
        if (jSONObject.has(OTUXParamsKeys.OT_UX_BORDER_WIDTH)) {
            jVar.g = jSONObject.getString(OTUXParamsKeys.OT_UX_BORDER_WIDTH);
        }
        if (jSONObject.has(OTUXParamsKeys.OT_UX_BORDER_RADIUS)) {
            jVar.h = jSONObject.getString(OTUXParamsKeys.OT_UX_BORDER_RADIUS);
        }
        if (jSONObject.has(OTUXParamsKeys.OT_UX_FONT_TYPE_FACE_KEY)) {
            ((k) ((m) jVar.j).d).e = jSONObject.getString(OTUXParamsKeys.OT_UX_FONT_TYPE_FACE_KEY);
        }
        return jVar;
    }

    public static m g(JSONObject jSONObject) {
        m mVar = new m();
        mVar.d = d(jSONObject);
        if (jSONObject.has(OTUXParamsKeys.OT_UX_TEXT_ALIGNMENT)) {
            mVar.f = jSONObject.getString(OTUXParamsKeys.OT_UX_TEXT_ALIGNMENT);
        }
        if (jSONObject.has(OTUXParamsKeys.OT_UX_TEXT_COLOR)) {
            mVar.b = jSONObject.getString(OTUXParamsKeys.OT_UX_TEXT_COLOR);
        }
        return mVar;
    }

    public final JSONObject b() {
        JSONObject jSONObject = this.a;
        if (jSONObject.has(OTUXParamsKeys.OT_UI_CONFIG)) {
            return jSONObject.getJSONObject(OTUXParamsKeys.OT_UI_CONFIG);
        }
        return null;
    }

    public final s c() {
        JSONObject jSONObjectB = b();
        s sVar = null;
        JSONObject jSONObject = (jSONObjectB == null || !jSONObjectB.has(OTUXParamsKeys.OT_GLOBAL_THEME)) ? null : jSONObjectB.getJSONObject(OTUXParamsKeys.OT_GLOBAL_THEME);
        if (jSONObject != null) {
            sVar = new s();
            sVar.c = true;
            if (jSONObject.has(OTUXParamsKeys.OT_UX_LINK_UNDERLINE)) {
                sVar.c = jSONObject.getBoolean(OTUXParamsKeys.OT_UX_LINK_UNDERLINE);
            }
            if (jSONObject.has(OTUXParamsKeys.OT_UX_LINK_COLOR)) {
                sVar.b = jSONObject.getString(OTUXParamsKeys.OT_UX_LINK_COLOR);
            }
        }
        return sVar;
    }
}

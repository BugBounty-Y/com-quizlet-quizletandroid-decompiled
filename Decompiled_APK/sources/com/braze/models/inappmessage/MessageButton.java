package com.braze.models.inappmessage;

import android.graphics.Color;
import android.net.Uri;
import com.braze.enums.inappmessage.ClickAction;
import com.braze.models.IPutIntoJson;
import com.braze.support.BrazeLogger;
import java.util.Locale;
import java.util.NoSuchElementException;
import kotlin.Metadata;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;
import org.json.JSONException;
import org.json.JSONObject;

@Metadata
/* loaded from: classes.dex */
public class MessageButton implements IPutIntoJson<JSONObject>, IInAppMessageThemeable {
    public static final k Companion = new k();
    private static final String TAG = BrazeLogger.getBrazeLogTag((Class<?>) MessageButton.class);
    private int backgroundColor;
    private int borderColor;
    private ClickAction clickAction;
    private com.braze.models.theme.b darkTheme;
    private int id;
    private JSONObject jsonObject;
    private boolean openUriInWebview;
    private String text;
    private int textColor;
    private Uri uri;

    /* JADX WARN: Illegal instructions before constructor call */
    public MessageButton(JSONObject jsonObject, JSONObject jSONObject) throws JSONException {
        ClickAction clickAction;
        String upperCase;
        int i;
        Intrinsics.checkNotNullParameter(jsonObject, "jsonObject");
        int iOptInt = jsonObject.optInt("id", -1);
        ClickAction clickAction2 = ClickAction.NEWS_FEED;
        try {
            String string = jsonObject.getString("click_action");
            Intrinsics.checkNotNullExpressionValue(string, "getString(...)");
            Locale US = Locale.US;
            Intrinsics.checkNotNullExpressionValue(US, "US");
            upperCase = string.toUpperCase(US);
            Intrinsics.checkNotNullExpressionValue(upperCase, "toUpperCase(...)");
        } catch (Exception unused) {
            clickAction = clickAction2;
        }
        for (ClickAction clickAction3 : ClickAction.values()) {
            if (Intrinsics.b(clickAction3.name(), upperCase)) {
                clickAction = clickAction3;
                String strOptString = jsonObject.optString("uri");
                String strOptString2 = jsonObject.optString("text");
                Intrinsics.checkNotNullExpressionValue(strOptString2, "optString(...)");
                this(jsonObject, jSONObject, iOptInt, clickAction, strOptString, strOptString2, jsonObject.optInt("bg_color"), jsonObject.optInt("text_color"), jsonObject.optBoolean("use_webview", false), jsonObject.optInt("border_color"));
                return;
            }
        }
        throw new NoSuchElementException("Array contains no element matching the predicate.");
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String enableDarkTheme$lambda$2$lambda$1() {
        return "Cannot apply dark theme with a null themes wrapper";
    }

    @Override // com.braze.models.inappmessage.IInAppMessageThemeable
    public void enableDarkTheme() {
        com.braze.models.theme.b bVar = this.darkTheme;
        if (bVar == null) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, TAG, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new com.braze.models.j(26), 14, (Object) null);
            return;
        }
        Integer num = bVar.a;
        if (num != null) {
            this.backgroundColor = num.intValue();
        }
        Integer num2 = bVar.b;
        if (num2 != null) {
            this.textColor = num2.intValue();
        }
        Integer num3 = bVar.c;
        if (num3 != null) {
            this.borderColor = num3.intValue();
        }
    }

    public final int getBackgroundColor() {
        return this.backgroundColor;
    }

    public final int getBorderColor() {
        return this.borderColor;
    }

    public final ClickAction getClickAction() {
        return this.clickAction;
    }

    public final boolean getOpenUriInWebview() {
        return this.openUriInWebview;
    }

    public final String getStringId() {
        return String.valueOf(this.id);
    }

    public final String getText() {
        return this.text;
    }

    public final int getTextColor() {
        return this.textColor;
    }

    public final Uri getUri() {
        return this.uri;
    }

    @Override // com.braze.models.IPutIntoJson
    public JSONObject forJsonPut() throws JSONException {
        try {
            JSONObject jSONObject = new JSONObject();
            jSONObject.put("id", this.id);
            jSONObject.put("click_action", this.clickAction.toString());
            Uri uri = this.uri;
            if (uri != null) {
                jSONObject.put("uri", String.valueOf(uri));
            }
            jSONObject.putOpt("text", this.text);
            jSONObject.put("bg_color", this.backgroundColor);
            jSONObject.put("text_color", this.textColor);
            jSONObject.put("use_webview", this.openUriInWebview);
            jSONObject.put("border_color", this.borderColor);
            return jSONObject;
        } catch (JSONException unused) {
            return this.jsonObject;
        }
    }

    private MessageButton(JSONObject jSONObject, JSONObject jSONObject2, int i, ClickAction clickAction, String str, String str2, int i2, int i3, boolean z, int i4) {
        this.id = -1;
        this.clickAction = ClickAction.NONE;
        int color = Color.parseColor("#1B78CF");
        this.backgroundColor = color;
        this.textColor = -1;
        this.borderColor = color;
        this.jsonObject = jSONObject;
        this.id = i;
        this.clickAction = clickAction;
        if (clickAction == ClickAction.URI && str != null && !StringsKt.O(str)) {
            this.uri = Uri.parse(str);
        }
        this.text = str2;
        this.backgroundColor = i2;
        this.textColor = i3;
        this.openUriInWebview = z;
        this.borderColor = i4;
        this.darkTheme = jSONObject2 != null ? new com.braze.models.theme.b(jSONObject2) : null;
    }
}

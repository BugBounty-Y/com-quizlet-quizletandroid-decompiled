package com.braze.models.inappmessage;

import android.graphics.Color;
import android.net.Uri;
import androidx.camera.camera2.internal.AbstractC0147y;
import com.amazon.device.ads.DtbDeviceData;
import com.braze.enums.inappmessage.ClickAction;
import com.braze.enums.inappmessage.CropType;
import com.braze.enums.inappmessage.DismissType;
import com.braze.enums.inappmessage.MessageType;
import com.braze.enums.inappmessage.Orientation;
import com.braze.enums.inappmessage.TextAlign;
import com.braze.managers.c0;
import com.braze.support.BrazeLogger;
import com.braze.support.JsonUtils;
import com.braze.support.n;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.concurrent.atomic.AtomicBoolean;
import kotlin.Metadata;
import kotlin.collections.K;
import kotlin.collections.V;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;
import kotlinx.coroutines.E;
import org.json.JSONException;
import org.json.JSONObject;

@Metadata
/* loaded from: classes.dex */
public abstract class InAppMessageBase implements IInAppMessage, IInAppMessageThemeable {
    public static final a Companion = new a();
    private boolean animateIn;
    private boolean animateOut;
    private int backgroundColor;
    private c0 brazeManager;
    private final AtomicBoolean clickLogged;
    private CropType cropType;
    private DismissType dismissType;
    private int durationInMilliseconds;
    private long expirationTimestamp;
    private Map<String, String> extras;
    private String icon;
    private int iconBackgroundColor;
    private int iconColor;
    private final AtomicBoolean impressionLogged;
    private com.braze.models.theme.a inAppMessageDarkThemeWrapper;
    private ClickAction internalClickAction;
    private Uri internalUri;
    private boolean isTestSend;
    private JSONObject jsonObject;
    private String message;
    private String messageExtras;
    private TextAlign messageTextAlign;
    private int messageTextColor;
    private boolean openUriInWebView;
    private Orientation orientation;

    public /* synthetic */ InAppMessageBase(JSONObject jSONObject, c0 c0Var, boolean z, boolean z2, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this(jSONObject, c0Var, (i & 4) != 0 ? false : z, (i & 8) != 0 ? false : z2);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String _set_durationInMilliseconds_$lambda$0(int i) {
        return AbstractC0147y.c(i, "Requested in-app message duration ", " is lower than the minimum of 999. Defaulting to 5000 milliseconds.");
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String _set_durationInMilliseconds_$lambda$1(int i) {
        return AbstractC0147y.c(i, "Set in-app message duration to ", " milliseconds.");
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String enableDarkTheme$lambda$6() {
        return "Cannot apply dark theme with a null themes wrapper";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String forJsonPut$lambda$9() {
        return "Failed to construct json for in-app message";
    }

    private final boolean handleLogClick(String str) {
        String triggerId = getTriggerId();
        if (triggerId == null || StringsKt.O(triggerId)) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new com.braze.models.j(12), 7, (Object) null);
            return false;
        }
        c0 c0Var = this.brazeManager;
        if (c0Var == null) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new com.braze.models.j(10), 6, (Object) null);
            return false;
        }
        if (getMessageType() != MessageType.HTML && this.clickLogged.get()) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.I, (Throwable) null, false, (Function0) new com.braze.models.j(11), 6, (Object) null);
            return false;
        }
        this.clickLogged.set(true);
        E.A(com.braze.coroutine.f.a, null, null, new b(str, triggerId, c0Var, null), 3);
        return true;
    }

    public static /* synthetic */ boolean handleLogClick$default(InAppMessageBase inAppMessageBase, String str, int i, Object obj) {
        if (obj != null) {
            throw new UnsupportedOperationException("Super calls with default arguments not supported in this target, function: handleLogClick");
        }
        if ((i & 1) != 0) {
            str = null;
        }
        return inAppMessageBase.handleLogClick(str);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String handleLogClick$lambda$10() {
        return "Trigger id not found (this is expected for test sends). Not logging in-app message click.";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String handleLogClick$lambda$11() {
        return "Cannot log an in-app message click because the BrazeManager is null.";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String handleLogClick$lambda$12() {
        return "Click already logged for this in-app message. Ignoring.";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String logImpression$lambda$3() {
        return "Trigger id not found (this is expected for test sends). Not logging in-app message impression.";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String logImpression$lambda$4() {
        return "Cannot log an in-app message impression because the BrazeManager is null.";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String logImpression$lambda$5() {
        return "Impression already logged for this in-app message. Ignoring.";
    }

    @Override // com.braze.models.inappmessage.IInAppMessageThemeable
    public void enableDarkTheme() {
        com.braze.models.theme.a aVar = this.inAppMessageDarkThemeWrapper;
        if (aVar == null) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new com.braze.models.j(9), 7, (Object) null);
            return;
        }
        Integer num = aVar.a;
        if (num != null) {
            setBackgroundColor(num.intValue());
        }
        Integer num2 = aVar.d;
        if (num2 != null) {
            setIconColor(num2.intValue());
        }
        Integer num3 = aVar.e;
        if (num3 != null) {
            setIconBackgroundColor(num3.intValue());
        }
        Integer num4 = aVar.b;
        if (num4 != null) {
            setMessageTextColor(num4.intValue());
        }
    }

    @Override // com.braze.models.inappmessage.IInAppMessage
    public boolean getAnimateIn() {
        return this.animateIn;
    }

    @Override // com.braze.models.inappmessage.IInAppMessage
    public boolean getAnimateOut() {
        return this.animateOut;
    }

    public int getBackgroundColor() {
        return this.backgroundColor;
    }

    public final c0 getBrazeManager() {
        return this.brazeManager;
    }

    @Override // com.braze.models.inappmessage.IInAppMessage
    public ClickAction getClickAction() {
        return this.internalClickAction;
    }

    @Override // com.braze.models.inappmessage.IInAppMessage
    public CropType getCropType() {
        return this.cropType;
    }

    @Override // com.braze.models.inappmessage.IInAppMessage
    public DismissType getDismissType() {
        return this.dismissType;
    }

    @Override // com.braze.models.inappmessage.IInAppMessage
    public int getDurationInMilliseconds() {
        return this.durationInMilliseconds;
    }

    @Override // com.braze.models.inappmessage.IInAppMessage
    public long getExpirationTimestamp() {
        return this.expirationTimestamp;
    }

    @Override // com.braze.models.inappmessage.IInAppMessage
    public Map<String, String> getExtras() {
        return this.extras;
    }

    public String getIcon() {
        return this.icon;
    }

    public int getIconBackgroundColor() {
        return this.iconBackgroundColor;
    }

    public int getIconColor() {
        return this.iconColor;
    }

    public final com.braze.models.theme.a getInAppMessageDarkThemeWrapper() {
        return this.inAppMessageDarkThemeWrapper;
    }

    public final JSONObject getJsonObject() {
        return this.jsonObject;
    }

    public String getMessage() {
        return this.message;
    }

    public String getMessageExtras() {
        return this.messageExtras;
    }

    public TextAlign getMessageTextAlign() {
        return this.messageTextAlign;
    }

    public int getMessageTextColor() {
        return this.messageTextColor;
    }

    @Override // com.braze.models.inappmessage.IInAppMessage
    public boolean getOpenUriInWebView() {
        return this.openUriInWebView;
    }

    @Override // com.braze.models.inappmessage.IInAppMessage
    public Orientation getOrientation() {
        return this.orientation;
    }

    @Override // com.braze.models.inappmessage.IInAppMessage
    public List<String> getRemoteAssetPathsForPrefetch() {
        return K.a;
    }

    public final String getTriggerId() {
        JSONObject jSONObject = this.jsonObject;
        if (jSONObject != null) {
            return jSONObject.optString("trigger_id");
        }
        return null;
    }

    @Override // com.braze.models.inappmessage.IInAppMessage
    public Uri getUri() {
        return this.internalUri;
    }

    @Override // com.braze.models.inappmessage.IInAppMessage
    public boolean isControl() {
        JSONObject jSONObject = this.jsonObject;
        return jSONObject != null && jSONObject.optBoolean("is_control");
    }

    public boolean isTestSend() {
        return this.isTestSend;
    }

    @Override // com.braze.models.inappmessage.IInAppMessage
    public boolean logClick() {
        return handleLogClick$default(this, null, 1, null);
    }

    @Override // com.braze.models.inappmessage.IInAppMessage
    public boolean logImpression() {
        String triggerId = getTriggerId();
        if (triggerId == null || StringsKt.O(triggerId)) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.D, (Throwable) null, false, (Function0) new com.braze.models.j(8), 6, (Object) null);
            return false;
        }
        c0 c0Var = this.brazeManager;
        if (c0Var == null) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new com.braze.models.j(6), 6, (Object) null);
            return false;
        }
        if (this.impressionLogged.get()) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.I, (Throwable) null, false, (Function0) new com.braze.models.j(7), 6, (Object) null);
            return false;
        }
        this.impressionLogged.set(true);
        E.A(com.braze.coroutine.f.a, null, null, new c(triggerId, this, c0Var, null), 3);
        return true;
    }

    @Override // com.braze.models.inappmessage.IInAppMessage
    public void onAfterClosed() {
        String triggerId = getTriggerId();
        if (triggerId == null || triggerId.length() == 0) {
            return;
        }
        E.A(com.braze.coroutine.f.a, null, null, new d(this, null), 3);
    }

    @Override // com.braze.models.inappmessage.IInAppMessage
    public void setAnimateIn(boolean z) {
        this.animateIn = z;
    }

    @Override // com.braze.models.inappmessage.IInAppMessage
    public void setAnimateOut(boolean z) {
        this.animateOut = z;
    }

    public void setBackgroundColor(int i) {
        this.backgroundColor = i;
    }

    public void setCropType(CropType cropType) {
        Intrinsics.checkNotNullParameter(cropType, "<set-?>");
        this.cropType = cropType;
    }

    public void setDismissType(DismissType dismissType) {
        Intrinsics.checkNotNullParameter(dismissType, "<set-?>");
        this.dismissType = dismissType;
    }

    public void setDurationInMilliseconds(int i) {
        if (i < 999) {
            this.durationInMilliseconds = 5000;
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new com.braze.enums.i(i, 3), 7, (Object) null);
        } else {
            this.durationInMilliseconds = i;
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new com.braze.enums.i(i, 4), 7, (Object) null);
        }
    }

    @Override // com.braze.models.inappmessage.IInAppMessage
    public void setExpirationTimestamp(long j) {
        this.expirationTimestamp = j;
    }

    public void setExtras(Map<String, String> map) {
        Intrinsics.checkNotNullParameter(map, "<set-?>");
        this.extras = map;
    }

    public void setIcon(String str) {
        this.icon = str;
    }

    public void setIconBackgroundColor(int i) {
        this.iconBackgroundColor = i;
    }

    public void setIconColor(int i) {
        this.iconColor = i;
    }

    @Override // com.braze.models.inappmessage.IInAppMessage
    public void setLocalPrefetchedAssetPaths(Map<String, String> remotePathToLocalAssetMap) {
        Intrinsics.checkNotNullParameter(remotePathToLocalAssetMap, "remotePathToLocalAssetMap");
    }

    public void setMessage(String str) {
        this.message = str;
    }

    public void setMessageExtras(String str) {
        this.messageExtras = str;
    }

    public void setMessageTextAlign(TextAlign textAlign) {
        Intrinsics.checkNotNullParameter(textAlign, "<set-?>");
        this.messageTextAlign = textAlign;
    }

    public void setMessageTextColor(int i) {
        this.messageTextColor = i;
    }

    public void setOpenUriInWebView(boolean z) {
        this.openUriInWebView = z;
    }

    public void setOrientation(Orientation orientation) {
        Intrinsics.checkNotNullParameter(orientation, "<set-?>");
        this.orientation = orientation;
    }

    @Override // com.braze.models.inappmessage.IInAppMessage
    public void setTestSend(boolean z) {
        this.isTestSend = z;
    }

    public InAppMessageBase(JSONObject inAppMessageJson, c0 brazeManager, boolean z, boolean z2) throws JSONException {
        String upperCase;
        String upperCase2;
        int i;
        String upperCase3;
        int i2;
        Intrinsics.checkNotNullParameter(inAppMessageJson, "json");
        Intrinsics.checkNotNullParameter(brazeManager, "brazeManager");
        this.internalClickAction = ClickAction.NONE;
        this.extras = V.c();
        this.animateIn = true;
        this.animateOut = true;
        this.dismissType = DismissType.AUTO_DISMISS;
        this.durationInMilliseconds = 5000;
        Orientation orientation = Orientation.ANY;
        this.orientation = orientation;
        this.cropType = CropType.FIT_CENTER;
        this.messageTextAlign = TextAlign.CENTER;
        this.expirationTimestamp = -1L;
        this.iconBackgroundColor = Color.parseColor("#ff0073d5");
        this.messageTextColor = Color.parseColor("#555555");
        this.backgroundColor = -1;
        this.iconColor = -1;
        this.impressionLogged = new AtomicBoolean(false);
        this.clickLogged = new AtomicBoolean(false);
        this.jsonObject = inAppMessageJson;
        this.brazeManager = brazeManager;
        setMessage(inAppMessageJson.optString("message"));
        setAnimateIn(inAppMessageJson.optBoolean("animate_in", true));
        setAnimateOut(inAppMessageJson.optBoolean("animate_out", true));
        setDurationInMilliseconds(inAppMessageJson.optInt("duration"));
        setIcon(inAppMessageJson.optString("icon"));
        try {
            String string = inAppMessageJson.getString(DtbDeviceData.DEVICE_DATA_ORIENTATION_KEY);
            Intrinsics.checkNotNullExpressionValue(string, "getString(...)");
            Locale US = Locale.US;
            Intrinsics.checkNotNullExpressionValue(US, "US");
            upperCase3 = string.toUpperCase(US);
            Intrinsics.checkNotNullExpressionValue(upperCase3, "toUpperCase(...)");
        } catch (Exception unused) {
        }
        for (Orientation orientation2 : Orientation.values()) {
            if (Intrinsics.b(orientation2.name(), upperCase3)) {
                orientation = orientation2;
                setOrientation(orientation);
                setOpenUriInWebView(inAppMessageJson.optBoolean("use_webview", false));
                setIconBackgroundColor(inAppMessageJson.optInt("icon_bg_color"));
                setMessageTextColor(inAppMessageJson.optInt("text_color"));
                setBackgroundColor(inAppMessageJson.optInt("bg_color"));
                setIconColor(inAppMessageJson.optInt("icon_color"));
                this.impressionLogged.set(z);
                this.clickLogged.set(z2);
                setExtras(JsonUtils.convertJSONObjectToMap(inAppMessageJson.optJSONObject("extras")));
                if (inAppMessageJson.has("message_extras")) {
                    setMessageExtras(inAppMessageJson.optString("message_extras"));
                }
                String strOptString = inAppMessageJson.optString("uri");
                ClickAction clickAction = ClickAction.NONE;
                try {
                    String string2 = inAppMessageJson.getString("click_action");
                    Intrinsics.checkNotNullExpressionValue(string2, "getString(...)");
                    Locale US2 = Locale.US;
                    Intrinsics.checkNotNullExpressionValue(US2, "US");
                    upperCase2 = string2.toUpperCase(US2);
                    Intrinsics.checkNotNullExpressionValue(upperCase2, "toUpperCase(...)");
                } catch (Exception unused2) {
                }
                for (ClickAction clickAction2 : ClickAction.values()) {
                    if (Intrinsics.b(clickAction2.name(), upperCase2)) {
                        clickAction = clickAction2;
                        if (clickAction == ClickAction.URI && strOptString != null && !StringsKt.O(strOptString)) {
                            this.internalUri = Uri.parse(strOptString);
                        }
                        this.internalClickAction = clickAction;
                        DismissType dismissType = DismissType.AUTO_DISMISS;
                        try {
                            String string3 = inAppMessageJson.getString("message_close");
                            Intrinsics.checkNotNullExpressionValue(string3, "getString(...)");
                            Locale US3 = Locale.US;
                            Intrinsics.checkNotNullExpressionValue(US3, "US");
                            upperCase = string3.toUpperCase(US3);
                            Intrinsics.checkNotNullExpressionValue(upperCase, "toUpperCase(...)");
                        } catch (Exception unused3) {
                        }
                        for (DismissType dismissType2 : DismissType.values()) {
                            if (Intrinsics.b(dismissType2.name(), upperCase)) {
                                dismissType = dismissType2;
                                setDismissType(dismissType == DismissType.SWIPE ? DismissType.MANUAL : dismissType);
                                String str = n.a;
                                Intrinsics.checkNotNullParameter(inAppMessageJson, "inAppMessageJson");
                                JSONObject jSONObjectOptJSONObject = inAppMessageJson.optJSONObject("themes");
                                JSONObject jSONObjectOptJSONObject2 = jSONObjectOptJSONObject != null ? jSONObjectOptJSONObject.optJSONObject("dark") : null;
                                this.inAppMessageDarkThemeWrapper = jSONObjectOptJSONObject2 != null ? new com.braze.models.theme.a(jSONObjectOptJSONObject2) : null;
                                inAppMessageJson.put("is_test_send", isTestSend());
                                return;
                            }
                        }
                        throw new NoSuchElementException("Array contains no element matching the predicate.");
                    }
                }
                throw new NoSuchElementException("Array contains no element matching the predicate.");
            }
        }
        throw new NoSuchElementException("Array contains no element matching the predicate.");
    }

    @Override // com.braze.models.IPutIntoJson
    public JSONObject forJsonPut() throws JSONException {
        JSONObject jSONObject = this.jsonObject;
        if (jSONObject != null) {
            return jSONObject;
        }
        JSONObject jSONObject2 = new JSONObject();
        try {
            jSONObject2.putOpt("message", getMessage());
            jSONObject2.put("duration", getDurationInMilliseconds());
            jSONObject2.putOpt("trigger_id", getTriggerId());
            jSONObject2.putOpt("click_action", getClickAction().toString());
            jSONObject2.putOpt("message_close", getDismissType().toString());
            if (getUri() != null) {
                jSONObject2.put("uri", String.valueOf(getUri()));
            }
            jSONObject2.put("use_webview", getOpenUriInWebView());
            jSONObject2.put("animate_in", getAnimateIn());
            jSONObject2.put("animate_out", getAnimateOut());
            jSONObject2.put("bg_color", getBackgroundColor());
            jSONObject2.put("text_color", getMessageTextColor());
            jSONObject2.put("icon_color", getIconColor());
            jSONObject2.put("icon_bg_color", getIconBackgroundColor());
            jSONObject2.putOpt("icon", getIcon());
            jSONObject2.putOpt("crop_type", getCropType().toString());
            jSONObject2.putOpt(DtbDeviceData.DEVICE_DATA_ORIENTATION_KEY, getOrientation().toString());
            jSONObject2.putOpt("text_align_message", getMessageTextAlign().toString());
            jSONObject2.putOpt("is_control", Boolean.valueOf(isControl()));
            jSONObject2.put("is_test_send", isTestSend());
            if (!getExtras().isEmpty()) {
                jSONObject2.put("extras", getExtras());
                return jSONObject2;
            }
        } catch (JSONException e) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.E, (Throwable) e, false, (Function0) new com.braze.models.j(5), 4, (Object) null);
        }
        return jSONObject2;
    }
}

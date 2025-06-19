package com.amazon.aps.ads.util.adview;

import android.webkit.JavascriptInterface;
import com.amazon.device.ads.DTBAdMRAIDController;
import com.amazon.device.ads.DtbCommonUtils;
import com.amazon.device.ads.MraidCommand;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3538u;
import com.quizlet.db.data.models.persisted.fields.DBUserFields;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final class f {
    public final e a;

    public f(e listener) {
        Intrinsics.checkNotNullParameter(listener, "listener");
        this.a = listener;
    }

    public final void a(JSONObject apsEvent) throws JSONException {
        Intrinsics.checkNotNullParameter(apsEvent, "apsEvent");
        String string = apsEvent.getString("subtype");
        if (DtbCommonUtils.isNullOrWhiteSpace(string)) {
            return;
        }
        e eVar = this.a;
        if (eVar.getApsMraidHandler() != null) {
            if (Intrinsics.b(string, "onAdLoaded")) {
                DTBAdMRAIDController apsMraidHandler = eVar.getApsMraidHandler();
                if (apsMraidHandler == null) {
                    return;
                }
                apsMraidHandler.onAdLoaded();
                return;
            }
            if (Intrinsics.b(string, "onAdFailedToLoad")) {
                DTBAdMRAIDController apsMraidHandler2 = eVar.getApsMraidHandler();
                if (apsMraidHandler2 == null) {
                    return;
                }
                apsMraidHandler2.onAdFailedToLoad();
                return;
            }
            String message = Intrinsics.k(" aps event not supported", string);
            Intrinsics.checkNotNullParameter(this, "<this>");
            Intrinsics.checkNotNullParameter(message, "message");
            AbstractC3538u.c(this);
            com.amazon.aps.ads.c.a();
        }
    }

    public final void b(JSONObject request) throws JSONException, IllegalAccessException, InstantiationException {
        Intrinsics.checkNotNullParameter(request, "request");
        String string = request.getString("subtype");
        Class<MraidCommand> clsFindMraidCommandByName = MraidCommand.findMraidCommandByName(string);
        e eVar = this.a;
        if (clsFindMraidCommandByName == null) {
            AbstractC3538u.b(this, "MRAID Command:" + ((Object) string) + " is not found");
            DTBAdMRAIDController apsMraidHandler = eVar.getApsMraidHandler();
            Intrinsics.d(apsMraidHandler);
            apsMraidHandler.fireErrorEvent(string, Intrinsics.k(" is not supported", string));
            DTBAdMRAIDController apsMraidHandler2 = eVar.getApsMraidHandler();
            Intrinsics.d(apsMraidHandler2);
            apsMraidHandler2.commandCompleted(string);
            return;
        }
        try {
            MraidCommand mraidCommandNewInstance = clsFindMraidCommandByName.newInstance();
            if (mraidCommandNewInstance == null) {
                throw new NullPointerException("null cannot be cast to non-null type com.amazon.device.ads.MraidCommand");
            }
            MraidCommand mraidCommand = mraidCommandNewInstance;
            AbstractC3538u.a(this, Intrinsics.k(mraidCommand.getName(), "execute command "));
            mraidCommand.execute(request.getJSONObject("arguments"), eVar.getApsMraidHandler());
        } catch (JSONException e) {
            throw e;
        } catch (Exception e2) {
            AbstractC3538u.b(this, "Error execution command " + ((Object) string) + ' ' + ((Object) e2.getLocalizedMessage()));
        }
    }

    public final void c(JSONObject request) throws JSONException {
        Intrinsics.checkNotNullParameter(request, "request");
        if ("log".equals(request.getString("subtype"))) {
            String string = request.getJSONObject("arguments").getString("message");
            Intrinsics.checkNotNullExpressionValue(string, "arguments.getString(\"message\")");
            AbstractC3538u.a(this, Intrinsics.k(string, "mraid:JSNative: "));
        }
    }

    /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue */
    public final void d(JSONObject videoEvent) throws JSONException {
        Intrinsics.checkNotNullParameter(videoEvent, "videoEvent");
        String string = videoEvent.getString("subtype");
        if (DtbCommonUtils.isNullOrWhiteSpace(string)) {
            return;
        }
        e eVar = this.a;
        if (eVar.getApsMraidHandler() != null) {
            if (string != null) {
                switch (string.hashCode()) {
                    case -1928679091:
                        if (string.equals("AD_VIDEO_PLAYER_COMPLETED")) {
                            DTBAdMRAIDController apsMraidHandler = eVar.getApsMraidHandler();
                            if (apsMraidHandler == null) {
                                return;
                            }
                            apsMraidHandler.onVideoCompleted();
                            return;
                        }
                        break;
                    case -100915287:
                        if (string.equals("AD_VIDEO_PLAYER_CLICKED")) {
                            DTBAdMRAIDController apsMraidHandler2 = eVar.getApsMraidHandler();
                            if (apsMraidHandler2 == null) {
                                return;
                            }
                            apsMraidHandler2.onAdClicked();
                            return;
                        }
                        break;
                    case 252691236:
                        if (string.equals("END_CARD_COMPANION_AD_START")) {
                            DTBAdMRAIDController apsMraidHandler3 = eVar.getApsMraidHandler();
                            if (apsMraidHandler3 == null) {
                                return;
                            }
                            apsMraidHandler3.startEndCardDisplayOMSDKSession();
                            return;
                        }
                        break;
                    case 604315076:
                        if (string.equals("AD_FAILED_TO_LOAD")) {
                            DTBAdMRAIDController apsMraidHandler4 = eVar.getApsMraidHandler();
                            if (apsMraidHandler4 == null) {
                                return;
                            }
                            apsMraidHandler4.onAdFailedToLoad();
                            return;
                        }
                        break;
                    case 1135343643:
                        if (string.equals("END_CARD_VIDEO_CLOSED")) {
                            DTBAdMRAIDController apsMraidHandler5 = eVar.getApsMraidHandler();
                            if (apsMraidHandler5 == null) {
                                return;
                            }
                            apsMraidHandler5.stopOMSDKSession();
                            return;
                        }
                        break;
                    case 1690844065:
                        if (string.equals("AD_LOADED")) {
                            DTBAdMRAIDController apsMraidHandler6 = eVar.getApsMraidHandler();
                            if (apsMraidHandler6 == null) {
                                return;
                            }
                            apsMraidHandler6.onAdLoaded();
                            return;
                        }
                        break;
                }
            }
            String message = Intrinsics.k(" video event not supported", string);
            Intrinsics.checkNotNullParameter(this, "<this>");
            Intrinsics.checkNotNullParameter(message, "message");
            AbstractC3538u.c(this);
            com.amazon.aps.ads.c.a();
        }
    }

    @JavascriptInterface
    public final void postMessage(String str) throws JSONException, IllegalAccessException, InstantiationException {
        try {
            JSONObject jSONObject = new JSONObject(str);
            if (!jSONObject.has(DBUserFields.Names.USER_UPGRADE_TYPE)) {
                AbstractC3538u.b(this, "Unrecognized bridge call");
                return;
            }
            String string = jSONObject.getString(DBUserFields.Names.USER_UPGRADE_TYPE);
            if ("service".equals(string)) {
                c(jSONObject);
                return;
            }
            if ("mraid".equals(string)) {
                b(jSONObject);
            } else if ("aps".equals(string)) {
                a(jSONObject);
            } else if ("apsvid".equals(string)) {
                d(jSONObject);
            }
        } catch (JSONException e) {
            AbstractC3538u.a(this, Intrinsics.k(e, "JSON conversion failed:"));
        }
    }
}

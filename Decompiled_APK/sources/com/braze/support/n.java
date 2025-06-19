package com.braze.support;

import com.braze.enums.inappmessage.MessageType;
import com.braze.managers.C1500m;
import com.braze.models.inappmessage.InAppMessageBase;
import com.braze.models.inappmessage.InAppMessageControl;
import com.braze.models.inappmessage.InAppMessageFull;
import com.braze.models.inappmessage.InAppMessageHtml;
import com.braze.models.inappmessage.InAppMessageHtmlFull;
import com.braze.models.inappmessage.InAppMessageModal;
import com.braze.models.inappmessage.InAppMessageSlideup;
import com.braze.support.BrazeLogger;
import com.quizlet.db.data.models.persisted.fields.DBUserFields;
import java.util.Locale;
import java.util.NoSuchElementException;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes.dex */
public abstract class n {
    public static final String a = BrazeLogger.INSTANCE.getBrazeLogTag("InAppMessageModelUtils");

    public static final InAppMessageBase a(JSONObject inAppMessageJson, C1500m brazeManager) throws JSONException {
        InAppMessageBase inAppMessageFull;
        String upperCase;
        Intrinsics.checkNotNullParameter(inAppMessageJson, "inAppMessageJson");
        Intrinsics.checkNotNullParameter(brazeManager, "brazeManager");
        try {
            Intrinsics.checkNotNullParameter(inAppMessageJson, "inAppMessageJson");
            if (inAppMessageJson.optBoolean("is_control", false)) {
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, a, BrazeLogger.Priority.D, (Throwable) null, false, (Function0) new v(22), 12, (Object) null);
                return new InAppMessageControl(inAppMessageJson, brazeManager);
            }
            try {
                String string = inAppMessageJson.getString(DBUserFields.Names.USER_UPGRADE_TYPE);
                Intrinsics.checkNotNullExpressionValue(string, "getString(...)");
                Locale US = Locale.US;
                Intrinsics.checkNotNullExpressionValue(US, "US");
                upperCase = string.toUpperCase(US);
                Intrinsics.checkNotNullExpressionValue(upperCase, "toUpperCase(...)");
            } catch (Exception unused) {
                messageType = null;
            }
            for (MessageType messageType : MessageType.values()) {
                if (Intrinsics.b(messageType.name(), upperCase)) {
                    if (messageType == null) {
                        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, a, BrazeLogger.Priority.I, (Throwable) null, false, (Function0) new com.braze.communication.dust.j(inAppMessageJson, 16), 12, (Object) null);
                        return null;
                    }
                    int i = m.a[messageType.ordinal()];
                    if (i == 1) {
                        inAppMessageFull = new InAppMessageFull(inAppMessageJson, brazeManager);
                    } else if (i == 2) {
                        inAppMessageFull = new InAppMessageModal(inAppMessageJson, brazeManager);
                    } else if (i == 3) {
                        inAppMessageFull = new InAppMessageSlideup(inAppMessageJson, brazeManager);
                    } else if (i == 4) {
                        inAppMessageFull = new InAppMessageHtmlFull(inAppMessageJson, brazeManager);
                    } else {
                        if (i != 5) {
                            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, a, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new com.braze.communication.dust.j(inAppMessageJson, 17), 12, (Object) null);
                            return null;
                        }
                        inAppMessageFull = new InAppMessageHtml(inAppMessageJson, brazeManager);
                    }
                    return inAppMessageFull;
                }
            }
            throw new NoSuchElementException("Array contains no element matching the predicate.");
        } catch (Exception e) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, a, BrazeLogger.Priority.E, (Throwable) e, false, (Function0) new com.braze.communication.dust.j(inAppMessageJson, 18), 8, (Object) null);
            return null;
        }
    }

    public static final String b(JSONObject jSONObject) {
        return "Unknown in-app message type. Returning null: " + JsonUtils.getPrettyPrintedString(jSONObject);
    }

    public static final String c(JSONObject jSONObject) {
        return "Failed to deserialize the in-app message: " + JsonUtils.getPrettyPrintedString(jSONObject) + ". Returning null.";
    }

    public static final String a() {
        return "Deserializing control in-app message.";
    }

    public static final String a(JSONObject jSONObject) {
        return "In-app message type was unknown for in-app message: " + JsonUtils.getPrettyPrintedString(jSONObject);
    }
}

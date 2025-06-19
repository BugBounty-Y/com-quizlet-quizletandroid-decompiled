package com.braze.models.inappmessage;

import android.graphics.Color;
import com.braze.enums.inappmessage.CropType;
import com.braze.enums.inappmessage.MessageType;
import com.braze.enums.inappmessage.SlideFrom;
import com.braze.enums.inappmessage.TextAlign;
import com.braze.managers.c0;
import com.braze.support.BrazeLogger;
import com.braze.support.JsonUtils;
import com.quizlet.db.data.models.persisted.fields.DBUserFields;
import kotlin.Metadata;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONException;
import org.json.JSONObject;

@Metadata
/* loaded from: classes.dex */
public final class InAppMessageSlideup extends InAppMessageWithImageBase {
    public static final Companion Companion = new Companion(null);
    private int chevronColor;
    private SlideFrom slideFrom;

    @Metadata
    public static final class Companion {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private Companion() {
        }
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public InAppMessageSlideup(JSONObject jsonObject, c0 brazeManager) {
        this(jsonObject, brazeManager, (SlideFrom) JsonUtils.optEnum(jsonObject, "slide_from", SlideFrom.class, SlideFrom.BOTTOM), jsonObject.optInt("close_btn_color"));
        Intrinsics.checkNotNullParameter(jsonObject, "jsonObject");
        Intrinsics.checkNotNullParameter(brazeManager, "brazeManager");
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String enableDarkTheme$lambda$0() {
        return "Cannot apply dark theme with a null themes wrapper";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String forJsonPut$lambda$2() {
        return "Error creating JSON.";
    }

    @Override // com.braze.models.inappmessage.InAppMessageBase, com.braze.models.inappmessage.IInAppMessageThemeable
    public void enableDarkTheme() {
        Integer num;
        super.enableDarkTheme();
        com.braze.models.theme.a inAppMessageDarkThemeWrapper = getInAppMessageDarkThemeWrapper();
        if (inAppMessageDarkThemeWrapper == null) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.D, (Throwable) null, false, (Function0) new com.braze.models.j(24), 6, (Object) null);
            return;
        }
        Integer num2 = inAppMessageDarkThemeWrapper.c;
        if ((num2 != null && num2.intValue() == -1) || (num = inAppMessageDarkThemeWrapper.c) == null) {
            return;
        }
        this.chevronColor = num.intValue();
    }

    public final int getChevronColor() {
        return this.chevronColor;
    }

    @Override // com.braze.models.inappmessage.IInAppMessage
    public MessageType getMessageType() {
        return MessageType.SLIDEUP;
    }

    public final SlideFrom getSlideFrom() {
        return this.slideFrom;
    }

    @Override // com.braze.models.inappmessage.InAppMessageBase, com.braze.models.IPutIntoJson
    public JSONObject forJsonPut() throws JSONException {
        JSONObject jsonObject = getJsonObject();
        if (jsonObject != null) {
            return jsonObject;
        }
        JSONObject jSONObjectForJsonPut = super.forJsonPut();
        try {
            jSONObjectForJsonPut.put("slide_from", this.slideFrom.toString());
            jSONObjectForJsonPut.put("close_btn_color", this.chevronColor);
            jSONObjectForJsonPut.put(DBUserFields.Names.USER_UPGRADE_TYPE, getMessageType().name());
            return jSONObjectForJsonPut;
        } catch (JSONException e) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.E, (Throwable) e, false, (Function0) new com.braze.models.j(25), 4, (Object) null);
            return jSONObjectForJsonPut;
        }
    }

    private InAppMessageSlideup(JSONObject jSONObject, c0 c0Var, SlideFrom slideFrom, int i) {
        super(jSONObject, c0Var);
        this.slideFrom = SlideFrom.BOTTOM;
        this.chevronColor = Color.parseColor("#9B9B9B");
        if (slideFrom != null) {
            this.slideFrom = slideFrom;
        }
        this.chevronColor = i;
        setCropType((CropType) JsonUtils.optEnum(jSONObject, "crop_type", CropType.class, CropType.FIT_CENTER));
        setMessageTextAlign((TextAlign) JsonUtils.optEnum(jSONObject, "text_align_message", TextAlign.class, TextAlign.START));
    }
}

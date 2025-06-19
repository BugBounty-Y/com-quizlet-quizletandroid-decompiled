package com.braze.models.inappmessage;

import android.graphics.Color;
import androidx.core.view.C;
import com.braze.enums.inappmessage.ImageStyle;
import com.braze.enums.inappmessage.TextAlign;
import com.braze.events.internal.f0;
import com.braze.managers.C1500m;
import com.braze.managers.c0;
import com.braze.support.BrazeLogger;
import com.braze.support.n;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.NoSuchElementException;
import kotlin.Metadata;
import kotlin.collections.B;
import kotlin.collections.CollectionsKt;
import kotlin.collections.J;
import kotlin.collections.K;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.ranges.l;
import kotlin.sequences.q;
import kotlin.text.StringsKt;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

@Metadata
/* loaded from: classes.dex */
public abstract class InAppMessageImmersiveBase extends InAppMessageWithImageBase implements IInAppMessageImmersive {
    public static final f Companion = new f();
    private String buttonIdClicked;
    private int closeButtonColor;
    private Integer frameColor;
    private String header;
    private TextAlign headerTextAlign;
    private int headerTextColor;
    private ImageStyle imageStyle;
    private List<? extends MessageButton> messageButtons;
    private boolean wasButtonClickLogged;

    /* JADX WARN: Illegal instructions before constructor call */
    public InAppMessageImmersiveBase(JSONObject inAppMessageJson, c0 brazeManager) throws JSONException {
        String str;
        int i;
        TextAlign textAlign;
        int i2;
        Iterator iterator;
        JSONObject jSONObjectOptJSONObject;
        String upperCase;
        int i3;
        String upperCase2;
        TextAlign[] textAlignArrValues;
        int length;
        int i4;
        String upperCase3;
        int i5;
        Intrinsics.checkNotNullParameter(inAppMessageJson, "jsonObject");
        Intrinsics.checkNotNullParameter(brazeManager, "brazeManager");
        String strOptString = inAppMessageJson.optString("header");
        Intrinsics.checkNotNullExpressionValue(strOptString, "optString(...)");
        int iOptInt = inAppMessageJson.optInt("header_text_color");
        int iOptInt2 = inAppMessageJson.optInt("close_btn_color");
        ImageStyle imageStyle = ImageStyle.TOP;
        try {
            String string = inAppMessageJson.getString("image_style");
            Intrinsics.checkNotNullExpressionValue(string, "getString(...)");
            Locale US = Locale.US;
            Intrinsics.checkNotNullExpressionValue(US, "US");
            upperCase3 = string.toUpperCase(US);
            Intrinsics.checkNotNullExpressionValue(upperCase3, "toUpperCase(...)");
        } catch (Exception unused) {
        }
        for (ImageStyle imageStyle2 : ImageStyle.values()) {
            if (Intrinsics.b(imageStyle2.name(), upperCase3)) {
                imageStyle = imageStyle2;
                TextAlign textAlign2 = TextAlign.CENTER;
                try {
                    String string2 = inAppMessageJson.getString("text_align_header");
                    Intrinsics.checkNotNullExpressionValue(string2, "getString(...)");
                    Locale US2 = Locale.US;
                    Intrinsics.checkNotNullExpressionValue(US2, "US");
                    upperCase2 = string2.toUpperCase(US2);
                    Intrinsics.checkNotNullExpressionValue(upperCase2, "toUpperCase(...)");
                    textAlignArrValues = TextAlign.values();
                    length = textAlignArrValues.length;
                    i4 = 0;
                } catch (Exception unused2) {
                    str = strOptString;
                }
                while (i4 < length) {
                    TextAlign textAlign3 = textAlignArrValues[i4];
                    str = strOptString;
                    if (Intrinsics.b(textAlign3.name(), upperCase2)) {
                        textAlign2 = textAlign3;
                        TextAlign textAlign4 = TextAlign.CENTER;
                        try {
                            String string3 = inAppMessageJson.getString("text_align_message");
                            Intrinsics.checkNotNullExpressionValue(string3, "getString(...)");
                            Locale US3 = Locale.US;
                            Intrinsics.checkNotNullExpressionValue(US3, "US");
                            upperCase = string3.toUpperCase(US3);
                            Intrinsics.checkNotNullExpressionValue(upperCase, "toUpperCase(...)");
                        } catch (Exception unused3) {
                            i = iOptInt2;
                            textAlign = textAlign4;
                        }
                        for (TextAlign textAlign5 : TextAlign.values()) {
                            if (Intrinsics.b(textAlign5.name(), upperCase)) {
                                i = iOptInt2;
                                textAlign = textAlign5;
                                this(inAppMessageJson, brazeManager, str, iOptInt, i, imageStyle, textAlign2, textAlign);
                                JSONArray jSONArrayOptJSONArray = inAppMessageJson.optJSONArray("btns");
                                String str2 = n.a;
                                Intrinsics.checkNotNullParameter(inAppMessageJson, "inAppMessageJson");
                                JSONObject jSONObjectOptJSONObject2 = inAppMessageJson.optJSONObject("themes");
                                JSONArray jSONArray = (jSONObjectOptJSONObject2 == null || (jSONObjectOptJSONObject = jSONObjectOptJSONObject2.optJSONObject("dark")) == null || (jSONArray = jSONObjectOptJSONObject.optJSONArray("btns")) == null) ? new JSONArray() : jSONArray;
                                ArrayList arrayList = new ArrayList();
                                if (jSONArrayOptJSONArray == null) {
                                    K.a.getClass();
                                    iterator = J.a;
                                    i2 = 0;
                                } else {
                                    i2 = 0;
                                    iterator = new C(q.h(q.e(CollectionsKt.D(l.h(0, jSONArrayOptJSONArray.length())), new g(jSONArrayOptJSONArray)), new h(jSONArrayOptJSONArray)));
                                }
                                Intrinsics.checkNotNullParameter(iterator, "<this>");
                                Intrinsics.checkNotNullParameter(iterator, "iterator");
                                int i6 = i2;
                                while (iterator.hasNext()) {
                                    int i7 = i6 + 1;
                                    if (i6 < 0) {
                                        B.p();
                                        throw null;
                                    }
                                    arrayList.add(new MessageButton((JSONObject) iterator.next(), jSONArray.optJSONObject(i6)));
                                    i6 = i7;
                                }
                                setMessageButtons(arrayList);
                                return;
                            }
                        }
                        throw new NoSuchElementException("Array contains no element matching the predicate.");
                    } else {
                        i4++;
                        strOptString = str;
                    }
                }
                str = strOptString;
                throw new NoSuchElementException("Array contains no element matching the predicate.");
            }
        }
        throw new NoSuchElementException("Array contains no element matching the predicate.");
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String enableDarkTheme$lambda$5() {
        return "Cannot apply dark theme with a null themes wrapper";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String logButtonClick$lambda$1() {
        return "Trigger id not found (this is expected for test sends). Not logging button click.";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String logButtonClick$lambda$2() {
        return "Button click already logged for this message. Ignoring.";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String logButtonClick$lambda$3() {
        return "Cannot log a button click because the BrazeManager is null.";
    }

    @Override // com.braze.models.inappmessage.InAppMessageBase, com.braze.models.inappmessage.IInAppMessageThemeable
    public void enableDarkTheme() {
        super.enableDarkTheme();
        com.braze.models.theme.a inAppMessageDarkThemeWrapper = getInAppMessageDarkThemeWrapper();
        if (inAppMessageDarkThemeWrapper == null) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new com.braze.models.j(20), 7, (Object) null);
            return;
        }
        Integer num = inAppMessageDarkThemeWrapper.g;
        if (num != null) {
            setFrameColor(num);
        }
        Integer num2 = inAppMessageDarkThemeWrapper.c;
        if (num2 != null) {
            setCloseButtonColor(num2.intValue());
        }
        Integer num3 = inAppMessageDarkThemeWrapper.f;
        if (num3 != null) {
            setHeaderTextColor(num3.intValue());
        }
        Iterator<MessageButton> it2 = getMessageButtons().iterator();
        while (it2.hasNext()) {
            it2.next().enableDarkTheme();
        }
    }

    @Override // com.braze.models.inappmessage.InAppMessageWithImageBase, com.braze.models.inappmessage.InAppMessageBase, com.braze.models.IPutIntoJson
    public JSONObject forJsonPut() throws JSONException {
        JSONObject jsonObject = getJsonObject();
        if (jsonObject != null) {
            return jsonObject;
        }
        JSONObject jSONObjectForJsonPut = super.forJsonPut();
        try {
            jSONObjectForJsonPut.putOpt("header", getHeader());
            jSONObjectForJsonPut.put("header_text_color", getHeaderTextColor());
            jSONObjectForJsonPut.put("close_btn_color", getCloseButtonColor());
            jSONObjectForJsonPut.putOpt("image_style", getImageStyle().toString());
            jSONObjectForJsonPut.putOpt("text_align_header", getHeaderTextAlign().toString());
            Integer frameColor = getFrameColor();
            if (frameColor != null) {
                jSONObjectForJsonPut.put("frame_color", frameColor.intValue());
            }
            JSONArray jSONArray = new JSONArray();
            Iterator<MessageButton> it2 = getMessageButtons().iterator();
            while (it2.hasNext()) {
                jSONArray.put(it2.next().forJsonPut());
            }
            jSONObjectForJsonPut.put("btns", jSONArray);
        } catch (JSONException unused) {
        }
        return jSONObjectForJsonPut;
    }

    public int getCloseButtonColor() {
        return this.closeButtonColor;
    }

    public Integer getFrameColor() {
        return this.frameColor;
    }

    public String getHeader() {
        return this.header;
    }

    public TextAlign getHeaderTextAlign() {
        return this.headerTextAlign;
    }

    public int getHeaderTextColor() {
        return this.headerTextColor;
    }

    @Override // com.braze.models.inappmessage.IInAppMessageImmersive
    public ImageStyle getImageStyle() {
        return this.imageStyle;
    }

    @Override // com.braze.models.inappmessage.IInAppMessageImmersive
    public List<MessageButton> getMessageButtons() {
        return this.messageButtons;
    }

    @Override // com.braze.models.inappmessage.IInAppMessageImmersive
    public boolean logButtonClick(MessageButton messageButton) {
        Intrinsics.checkNotNullParameter(messageButton, "messageButton");
        c0 brazeManager = getBrazeManager();
        String triggerId = getTriggerId();
        if (triggerId == null || StringsKt.O(triggerId)) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new com.braze.models.j(23), 7, (Object) null);
            return false;
        }
        if (this.wasButtonClickLogged) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.I, (Throwable) null, false, (Function0) new com.braze.models.j(21), 6, (Object) null);
            return false;
        }
        if (brazeManager == null) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new com.braze.models.j(22), 6, (Object) null);
            return false;
        }
        this.buttonIdClicked = messageButton.getStringId();
        com.braze.models.outgoing.event.a aVar = com.braze.models.outgoing.event.b.g;
        aVar.getClass();
        Intrinsics.checkNotNullParameter(triggerId, "triggerId");
        Intrinsics.checkNotNullParameter(messageButton, "messageButton");
        com.braze.models.i iVarI = aVar.i(triggerId, messageButton.getStringId());
        if (iVarI != null) {
            ((C1500m) brazeManager).a(iVarI);
        }
        this.wasButtonClickLogged = true;
        return true;
    }

    @Override // com.braze.models.inappmessage.InAppMessageBase, com.braze.models.inappmessage.IInAppMessage
    public void onAfterClosed() {
        String triggerId;
        String str;
        super.onAfterClosed();
        c0 brazeManager = getBrazeManager();
        if (!this.wasButtonClickLogged || (triggerId = getTriggerId()) == null || StringsKt.O(triggerId) || (str = this.buttonIdClicked) == null || StringsKt.O(str) || brazeManager == null) {
            return;
        }
        com.braze.triggers.events.d triggerEvent = new com.braze.triggers.events.d(getTriggerId(), this.buttonIdClicked);
        Intrinsics.checkNotNullParameter(triggerEvent, "triggerEvent");
        ((C1500m) brazeManager).d.b(new f0(triggerEvent), f0.class);
    }

    public void setCloseButtonColor(int i) {
        this.closeButtonColor = i;
    }

    public void setFrameColor(Integer num) {
        this.frameColor = num;
    }

    public void setHeader(String str) {
        this.header = str;
    }

    public void setHeaderTextAlign(TextAlign textAlign) {
        Intrinsics.checkNotNullParameter(textAlign, "<set-?>");
        this.headerTextAlign = textAlign;
    }

    public void setHeaderTextColor(int i) {
        this.headerTextColor = i;
    }

    public void setImageStyle(ImageStyle imageStyle) {
        Intrinsics.checkNotNullParameter(imageStyle, "<set-?>");
        this.imageStyle = imageStyle;
    }

    public void setMessageButtons(List<? extends MessageButton> list) {
        Intrinsics.checkNotNullParameter(list, "<set-?>");
        this.messageButtons = list;
    }

    private InAppMessageImmersiveBase(JSONObject jSONObject, c0 c0Var, String str, int i, int i2, ImageStyle imageStyle, TextAlign textAlign, TextAlign textAlign2) {
        super(jSONObject, c0Var);
        this.headerTextColor = Color.parseColor("#333333");
        this.closeButtonColor = Color.parseColor("#9B9B9B");
        this.messageButtons = K.a;
        this.imageStyle = ImageStyle.TOP;
        this.headerTextAlign = TextAlign.CENTER;
        setHeader(str);
        setHeaderTextColor(i);
        setCloseButtonColor(i2);
        if (jSONObject.has("frame_color")) {
            setFrameColor(Integer.valueOf(jSONObject.optInt("frame_color")));
        }
        setImageStyle(imageStyle);
        setHeaderTextAlign(textAlign);
        setMessageTextAlign(textAlign2);
    }
}

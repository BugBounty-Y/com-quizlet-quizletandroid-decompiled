package com.braze.ui;

import android.content.Context;
import android.webkit.JavascriptInterface;
import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.compose.ui.node.B;
import androidx.lifecycle.u0;
import androidx.navigation.U;
import com.braze.Braze;
import com.braze.BrazeUser;
import com.braze.enums.Gender;
import com.braze.enums.Month;
import com.braze.enums.NotificationSubscriptionType;
import com.braze.support.BrazeLogger;
import com.braze.triggers.managers.i;
import com.braze.triggers.managers.j;
import java.util.ArrayList;
import java.util.Locale;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.C;
import kotlin.text.StringsKt;
import org.jetbrains.annotations.NotNull;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

@Metadata
/* loaded from: classes.dex */
public class UserJavascriptInterfaceBase {

    @NotNull
    public static final Companion Companion = new Companion(null);

    @NotNull
    private final Context context;

    @Metadata
    public static final class Companion {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        /* JADX INFO: Access modifiers changed from: private */
        public final void runOnUser(Braze braze, Function1<? super BrazeUser, Unit> function1) {
            braze.getCurrentUser(new h(function1));
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static final void runOnUser$lambda$0(Function1 function1, BrazeUser it2) {
            Intrinsics.checkNotNullParameter(it2, "it");
            function1.invoke(it2);
        }

        private Companion() {
        }
    }

    public UserJavascriptInterfaceBase(@NotNull Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        this.context = context;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final Unit addAlias$lambda$28(String str, String str2, BrazeUser it2) {
        Intrinsics.checkNotNullParameter(it2, "it");
        it2.addAlias(str, str2);
        return Unit.a;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final Unit addToCustomAttributeArray$lambda$21(String str, String str2, BrazeUser it2) {
        Intrinsics.checkNotNullParameter(it2, "it");
        it2.addToCustomAttributeArray(str, str2);
        return Unit.a;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final Unit addToSubscriptionGroup$lambda$29(String str, BrazeUser it2) {
        Intrinsics.checkNotNullParameter(it2, "it");
        it2.addToSubscriptionGroup(str);
        return Unit.a;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String incrementCustomUserAttribute$lambda$23(String str) {
        return B.h("Failed to parse incrementCustomUserAttribute increment value '", str, '\'');
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final Unit incrementCustomUserAttribute$lambda$24(String str, Integer num, BrazeUser it2) {
        Intrinsics.checkNotNullParameter(it2, "it");
        it2.incrementCustomUserAttribute(str, num.intValue());
        return Unit.a;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String parseStringArrayFromJsonString$lambda$34() {
        return "Failed to parse custom attribute array";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final Unit removeFromCustomAttributeArray$lambda$22(String str, String str2, BrazeUser it2) {
        Intrinsics.checkNotNullParameter(it2, "it");
        it2.removeFromCustomAttributeArray(str, str2);
        return Unit.a;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final Unit removeFromSubscriptionGroup$lambda$30(String str, BrazeUser it2) {
        Intrinsics.checkNotNullParameter(it2, "it");
        it2.removeFromSubscriptionGroup(str);
        return Unit.a;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final Unit setCountry$lambda$9(String str, BrazeUser it2) {
        Intrinsics.checkNotNullParameter(it2, "it");
        it2.setCountry(str);
        return Unit.a;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String setCustomAttribute$lambda$31(String str, String str2) {
        return android.support.v4.media.session.a.m("Failed to parse custom attribute type for key: ", str, " and json string value: ", str2);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String setCustomAttribute$lambda$32(String str, String str2) {
        return android.support.v4.media.session.a.m("Failed to parse custom attribute type for key: ", str, " and json string value: ", str2);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String setCustomLocationAttribute$lambda$25(String str) {
        return B.h("Failed to parse setCustomLocationAttribute latitude value '", str, '\'');
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String setCustomLocationAttribute$lambda$26(String str) {
        return B.h("Failed to parse setCustomLocationAttribute longitude value '", str, '\'');
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final Unit setCustomLocationAttribute$lambda$27(String str, Double d, Double d2, BrazeUser it2) {
        Intrinsics.checkNotNullParameter(it2, "it");
        it2.setLocationCustomAttribute(str, d.doubleValue(), d2.doubleValue());
        return Unit.a;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String setCustomUserAttributeArray$lambda$19(String str) {
        return AbstractC0147y.d("Failed to set custom attribute array for key ", str);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final Unit setCustomUserAttributeArray$lambda$20(String str, String[] strArr, BrazeUser it2) {
        Intrinsics.checkNotNullParameter(it2, "it");
        it2.setCustomAttributeArray(str, strArr);
        return Unit.a;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final Unit setCustomUserAttributeJSON$lambda$18(UserJavascriptInterfaceBase userJavascriptInterfaceBase, String str, String str2, boolean z, BrazeUser it2) throws JSONException {
        Intrinsics.checkNotNullParameter(it2, "it");
        userJavascriptInterfaceBase.setCustomAttribute(it2, str, str2, z);
        return Unit.a;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String setDateOfBirth$lambda$5(String str) {
        return B.h("Failed to parse setDateOfBirth year value '", str, '\'');
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String setDateOfBirth$lambda$6(String str) {
        return AbstractC0147y.d("Failed to parse setDateOfBirth month for value ", str);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String setDateOfBirth$lambda$7(String str) {
        return B.h("Failed to parse setDateOfBirth day value '", str, '\'');
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final Unit setDateOfBirth$lambda$8(Integer num, Month month, Integer num2, BrazeUser it2) {
        Intrinsics.checkNotNullParameter(it2, "it");
        it2.setDateOfBirth(num.intValue(), month, num2.intValue());
        return Unit.a;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final Unit setEmail$lambda$2(String str, BrazeUser it2) {
        Intrinsics.checkNotNullParameter(it2, "it");
        it2.setEmail(str);
        return Unit.a;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String setEmailNotificationSubscriptionType$lambda$12(String str) {
        return AbstractC0147y.d("Failed to parse email subscription type in Braze HTML in-app message javascript interface with subscription ", str);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final Unit setEmailNotificationSubscriptionType$lambda$13(NotificationSubscriptionType notificationSubscriptionType, BrazeUser it2) {
        Intrinsics.checkNotNullParameter(it2, "it");
        it2.setEmailNotificationSubscriptionType(notificationSubscriptionType);
        return Unit.a;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final Unit setFirstName$lambda$0(String str, BrazeUser it2) {
        Intrinsics.checkNotNullParameter(it2, "it");
        it2.setFirstName(str);
        return Unit.a;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String setGender$lambda$3(String str) {
        return AbstractC0147y.d("Failed to parse gender in Braze HTML in-app message javascript interface with gender: ", str);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final Unit setGender$lambda$4(Gender gender, BrazeUser it2) {
        Intrinsics.checkNotNullParameter(it2, "it");
        it2.setGender(gender);
        return Unit.a;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final Unit setHomeCity$lambda$11(String str, BrazeUser it2) {
        Intrinsics.checkNotNullParameter(it2, "it");
        it2.setHomeCity(str);
        return Unit.a;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final Unit setLanguage$lambda$10(String str, BrazeUser it2) {
        Intrinsics.checkNotNullParameter(it2, "it");
        it2.setLanguage(str);
        return Unit.a;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final Unit setLastName$lambda$1(String str, BrazeUser it2) {
        Intrinsics.checkNotNullParameter(it2, "it");
        it2.setLastName(str);
        return Unit.a;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final Unit setLineId$lambda$17(String str, BrazeUser it2) {
        Intrinsics.checkNotNullParameter(it2, "it");
        it2.setLineId(str);
        return Unit.a;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final Unit setPhoneNumber$lambda$16(String str, BrazeUser it2) {
        Intrinsics.checkNotNullParameter(it2, "it");
        it2.setPhoneNumber(str);
        return Unit.a;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String setPushNotificationSubscriptionType$lambda$14(String str) {
        return AbstractC0147y.d("Failed to parse push subscription type in Braze HTML in-app message javascript interface with subscription: ", str);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final Unit setPushNotificationSubscriptionType$lambda$15(NotificationSubscriptionType notificationSubscriptionType, BrazeUser it2) {
        Intrinsics.checkNotNullParameter(it2, "it");
        it2.setPushNotificationSubscriptionType(notificationSubscriptionType);
        return Unit.a;
    }

    @JavascriptInterface
    public final void addAlias(@NotNull String alias, @NotNull String label) {
        Intrinsics.checkNotNullParameter(alias, "alias");
        Intrinsics.checkNotNullParameter(label, "label");
        Companion.runOnUser(Braze.Companion.getInstance(this.context), new e(2, alias, label));
    }

    @JavascriptInterface
    public final void addToCustomAttributeArray(@NotNull String key, @NotNull String value) {
        Intrinsics.checkNotNullParameter(key, "key");
        Intrinsics.checkNotNullParameter(value, "value");
        Companion.runOnUser(Braze.Companion.getInstance(this.context), new e(1, key, value));
    }

    @JavascriptInterface
    public final void addToSubscriptionGroup(@NotNull String subscriptionGroupId) {
        Intrinsics.checkNotNullParameter(subscriptionGroupId, "subscriptionGroupId");
        Companion.runOnUser(Braze.Companion.getInstance(this.context), new androidx.navigation.internal.h(subscriptionGroupId, 2));
    }

    @JavascriptInterface
    public final void incrementCustomUserAttribute(@NotNull String attribute, @NotNull String value) {
        Intrinsics.checkNotNullParameter(attribute, "attribute");
        Intrinsics.checkNotNullParameter(value, "value");
        Integer intOrNull = StringsKt.toIntOrNull(value);
        if (intOrNull == null) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new d(value, 4), 6, (Object) null);
        } else {
            Companion.runOnUser(Braze.Companion.getInstance(this.context), new u0(4, attribute, intOrNull));
        }
    }

    public final Month monthFromInt(@NotNull String month) {
        int iIntValue;
        Intrinsics.checkNotNullParameter(month, "month");
        Integer intOrNull = StringsKt.toIntOrNull(month);
        if (intOrNull == null || (iIntValue = intOrNull.intValue()) < 1 || iIntValue > 12) {
            return null;
        }
        return Month.Companion.getMonth(iIntValue - 1);
    }

    public final Gender parseGender(@NotNull String genderString) {
        Intrinsics.checkNotNullParameter(genderString, "genderString");
        Locale locale = Locale.US;
        String strK = B.k(locale, "US", genderString, locale, "toLowerCase(...)");
        Gender gender = Gender.MALE;
        if (Intrinsics.b(strK, gender.forJsonPut())) {
            return gender;
        }
        Gender gender2 = Gender.FEMALE;
        if (Intrinsics.b(strK, gender2.forJsonPut())) {
            return gender2;
        }
        Gender gender3 = Gender.OTHER;
        if (Intrinsics.b(strK, gender3.forJsonPut())) {
            return gender3;
        }
        Gender gender4 = Gender.UNKNOWN;
        if (Intrinsics.b(strK, gender4.forJsonPut())) {
            return gender4;
        }
        Gender gender5 = Gender.NOT_APPLICABLE;
        if (Intrinsics.b(strK, gender5.forJsonPut())) {
            return gender5;
        }
        Gender gender6 = Gender.PREFER_NOT_TO_SAY;
        if (Intrinsics.b(strK, gender6.forJsonPut())) {
            return gender6;
        }
        return null;
    }

    public final String[] parseStringArrayFromJsonString(String str) {
        try {
            JSONArray jSONArray = new JSONArray(str);
            int length = jSONArray.length();
            ArrayList arrayList = new ArrayList(length);
            for (int i = 0; i < length; i++) {
                arrayList.add(jSONArray.getString(i));
            }
            return (String[]) arrayList.toArray(new String[0]);
        } catch (Exception e) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.E, (Throwable) e, false, (Function0) new i(21), 4, (Object) null);
            return null;
        }
    }

    @JavascriptInterface
    public final void removeFromCustomAttributeArray(@NotNull String key, @NotNull String value) {
        Intrinsics.checkNotNullParameter(key, "key");
        Intrinsics.checkNotNullParameter(value, "value");
        Companion.runOnUser(Braze.Companion.getInstance(this.context), new e(0, key, value));
    }

    @JavascriptInterface
    public final void removeFromSubscriptionGroup(@NotNull String subscriptionGroupId) {
        Intrinsics.checkNotNullParameter(subscriptionGroupId, "subscriptionGroupId");
        Companion.runOnUser(Braze.Companion.getInstance(this.context), new androidx.navigation.internal.h(subscriptionGroupId, 3));
    }

    @JavascriptInterface
    public final void setCountry(String str) {
        Companion.runOnUser(Braze.Companion.getInstance(this.context), new androidx.navigation.internal.h(str, 4));
    }

    public final void setCustomAttribute(@NotNull BrazeUser user, @NotNull String key, @NotNull String jsonStringValue, boolean z) throws JSONException {
        Intrinsics.checkNotNullParameter(user, "user");
        Intrinsics.checkNotNullParameter(key, "key");
        Intrinsics.checkNotNullParameter(jsonStringValue, "jsonStringValue");
        try {
            Object obj = new JSONObject(jsonStringValue).get("value");
            if (obj instanceof String) {
                user.setCustomUserAttribute(key, (String) obj);
                return;
            }
            if (obj instanceof Boolean) {
                user.setCustomUserAttribute(key, ((Boolean) obj).booleanValue());
                return;
            }
            if (obj instanceof Integer) {
                user.setCustomUserAttribute(key, ((Number) obj).intValue());
                return;
            }
            if (obj instanceof Double) {
                user.setCustomUserAttribute(key, ((Number) obj).doubleValue());
            } else if (obj instanceof JSONObject) {
                user.setCustomUserAttribute(key, (JSONObject) obj, z);
            } else {
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new j(3, key, jsonStringValue), 6, (Object) null);
            }
        } catch (Exception e) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.E, (Throwable) e, false, (Function0) new j(4, key, jsonStringValue), 4, (Object) null);
        }
    }

    @JavascriptInterface
    public final void setCustomLocationAttribute(@NotNull String attribute, @NotNull String latitude, @NotNull String longitude) {
        Intrinsics.checkNotNullParameter(attribute, "attribute");
        Intrinsics.checkNotNullParameter(latitude, "latitude");
        Intrinsics.checkNotNullParameter(longitude, "longitude");
        Double dE = C.e(latitude);
        if (dE == null) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new d(latitude, 2), 6, (Object) null);
            return;
        }
        Double dE2 = C.e(longitude);
        if (dE2 == null) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new d(longitude, 3), 6, (Object) null);
        } else {
            Companion.runOnUser(Braze.Companion.getInstance(this.context), new androidx.lifecycle.compose.d(attribute, dE, dE2, 4));
        }
    }

    @JavascriptInterface
    public final void setCustomUserAttributeArray(@NotNull String key, String str) {
        Intrinsics.checkNotNullParameter(key, "key");
        String[] stringArrayFromJsonString = parseStringArrayFromJsonString(str);
        if (stringArrayFromJsonString == null) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new d(key, 6), 6, (Object) null);
        } else {
            Companion.runOnUser(Braze.Companion.getInstance(this.context), new u0(5, key, stringArrayFromJsonString));
        }
    }

    @JavascriptInterface
    public final void setCustomUserAttributeJSON(@NotNull String key, @NotNull String jsonStringValue, boolean z) {
        Intrinsics.checkNotNullParameter(key, "key");
        Intrinsics.checkNotNullParameter(jsonStringValue, "jsonStringValue");
        Companion.runOnUser(Braze.Companion.getInstance(this.context), new g(this, key, jsonStringValue, z));
    }

    @JavascriptInterface
    public final void setDateOfBirth(@NotNull String year, @NotNull String month, @NotNull String day) {
        Intrinsics.checkNotNullParameter(year, "year");
        Intrinsics.checkNotNullParameter(month, "month");
        Intrinsics.checkNotNullParameter(day, "day");
        Integer intOrNull = StringsKt.toIntOrNull(year);
        if (intOrNull == null) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new d(year, 8), 6, (Object) null);
            return;
        }
        Month monthMonthFromInt = monthFromInt(month);
        if (monthMonthFromInt == null) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new d(month, 9), 6, (Object) null);
            return;
        }
        Integer intOrNull2 = StringsKt.toIntOrNull(day);
        if (intOrNull2 == null) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new d(day, 1), 6, (Object) null);
        } else {
            Companion.runOnUser(Braze.Companion.getInstance(this.context), new androidx.lifecycle.compose.d(intOrNull, monthMonthFromInt, intOrNull2, 3));
        }
    }

    @JavascriptInterface
    public final void setEmail(String str) {
        Companion.runOnUser(Braze.Companion.getInstance(this.context), new androidx.navigation.internal.h(str, 8));
    }

    @JavascriptInterface
    public final void setEmailNotificationSubscriptionType(@NotNull String subscriptionType) {
        Intrinsics.checkNotNullParameter(subscriptionType, "subscriptionType");
        NotificationSubscriptionType notificationSubscriptionTypeSubscriptionTypeFromJavascriptString = subscriptionTypeFromJavascriptString(subscriptionType);
        if (notificationSubscriptionTypeSubscriptionTypeFromJavascriptString == null) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new d(subscriptionType, 0), 6, (Object) null);
        } else {
            Companion.runOnUser(Braze.Companion.getInstance(this.context), new f(notificationSubscriptionTypeSubscriptionTypeFromJavascriptString, 0));
        }
    }

    @JavascriptInterface
    public final void setFirstName(String str) {
        Companion.runOnUser(Braze.Companion.getInstance(this.context), new androidx.navigation.internal.h(str, 5));
    }

    @JavascriptInterface
    public final void setGender(@NotNull String genderString) {
        Intrinsics.checkNotNullParameter(genderString, "genderString");
        Gender gender = parseGender(genderString);
        if (gender == null) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new d(genderString, 5), 6, (Object) null);
        } else {
            Companion.runOnUser(Braze.Companion.getInstance(this.context), new U(gender, 6));
        }
    }

    @JavascriptInterface
    public final void setHomeCity(String str) {
        Companion.runOnUser(Braze.Companion.getInstance(this.context), new androidx.navigation.internal.h(str, 6));
    }

    @JavascriptInterface
    public final void setLanguage(String str) {
        Companion.runOnUser(Braze.Companion.getInstance(this.context), new androidx.navigation.internal.h(str, 1));
    }

    @JavascriptInterface
    public final void setLastName(String str) {
        Companion.runOnUser(Braze.Companion.getInstance(this.context), new androidx.navigation.internal.h(str, 10));
    }

    @JavascriptInterface
    public final void setLineId(String str) {
        Companion.runOnUser(Braze.Companion.getInstance(this.context), new androidx.navigation.internal.h(str, 9));
    }

    @JavascriptInterface
    public final void setPhoneNumber(String str) {
        Companion.runOnUser(Braze.Companion.getInstance(this.context), new androidx.navigation.internal.h(str, 7));
    }

    @JavascriptInterface
    public final void setPushNotificationSubscriptionType(@NotNull String subscriptionType) {
        Intrinsics.checkNotNullParameter(subscriptionType, "subscriptionType");
        NotificationSubscriptionType notificationSubscriptionTypeSubscriptionTypeFromJavascriptString = subscriptionTypeFromJavascriptString(subscriptionType);
        if (notificationSubscriptionTypeSubscriptionTypeFromJavascriptString == null) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new d(subscriptionType, 7), 6, (Object) null);
        } else {
            Companion.runOnUser(Braze.Companion.getInstance(this.context), new f(notificationSubscriptionTypeSubscriptionTypeFromJavascriptString, 1));
        }
    }

    public final NotificationSubscriptionType subscriptionTypeFromJavascriptString(String str) {
        return NotificationSubscriptionType.Companion.fromValue(str);
    }
}

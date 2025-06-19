package com.braze;

import androidx.lifecycle.C1247h;
import com.braze.enums.BrazeDateFormat;
import com.braze.enums.Gender;
import com.braze.enums.Month;
import com.braze.enums.NotificationSubscriptionType;
import com.braze.managers.C1500m;
import com.braze.managers.c0;
import com.braze.support.BrazeLogger;
import com.braze.support.DateTimeUtils;
import com.braze.support.JsonUtils;
import com.braze.support.ValidationUtils;
import java.util.ArrayList;
import java.util.concurrent.locks.ReentrantLock;
import kotlin.Metadata;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;
import org.json.JSONObject;

@Metadata
/* loaded from: classes.dex */
public final class BrazeUser {
    private final c0 brazeManager;
    private volatile String internalUserId;
    private final com.braze.managers.f0 locationManager;
    private final com.braze.storage.e0 serverConfigStorageProvider;
    private final com.braze.storage.h0 userCache;
    private final ReentrantLock userIdLock;

    public BrazeUser(com.braze.storage.h0 userCache, c0 brazeManager, String internalUserId, com.braze.managers.f0 locationManager, com.braze.storage.e0 serverConfigStorageProvider) {
        Intrinsics.checkNotNullParameter(userCache, "userCache");
        Intrinsics.checkNotNullParameter(brazeManager, "brazeManager");
        Intrinsics.checkNotNullParameter(internalUserId, "internalUserId");
        Intrinsics.checkNotNullParameter(locationManager, "locationManager");
        Intrinsics.checkNotNullParameter(serverConfigStorageProvider, "serverConfigStorageProvider");
        this.userCache = userCache;
        this.brazeManager = brazeManager;
        this.internalUserId = internalUserId;
        this.locationManager = locationManager;
        this.serverConfigStorageProvider = serverConfigStorageProvider;
        this.userIdLock = new ReentrantLock();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String _set_userId_$lambda$1(String str) {
        return AbstractC1484j.a("User object user id set to: ", str);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String addAlias$lambda$4() {
        return "Invalid alias parameter: alias is required to be non-null and non-empty. Not adding alias.";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String addAlias$lambda$5() {
        return "Invalid label parameter: label is required to be non-null and non-empty. Not adding alias.";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String addAlias$lambda$7(String str) {
        return AbstractC1484j.a("Failed to set alias: ", str);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String addToCustomAttributeArray$lambda$51() {
        return "Custom attribute key was invalid. Not adding to attribute array.";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String addToCustomAttributeArray$lambda$52(String str) {
        return AbstractC1475a.a("Failed to add custom attribute with key '", str, "'.");
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String addToSubscriptionGroup$lambda$27() {
        return "Invalid subscription group ID: subscription group ID is required to be non-null and non-empty. Not adding user to subscription group.";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String addToSubscriptionGroup$lambda$29(String str) {
        return AbstractC1484j.a("Failed to add user to subscription group ", str);
    }

    public static /* synthetic */ String i(Object obj, String str) {
        return setCustomAttribute$lambda$73$lambda$71(str, obj);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String incrementCustomUserAttribute$lambda$58(String str, int i) {
        return "Failed to increment custom attribute " + str + " by " + i + '.';
    }

    public static /* synthetic */ String k(Object obj, String str) {
        return setCustomAttribute$lambda$73$lambda$72(str, obj);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String removeFromCustomAttributeArray$lambda$53() {
        return "Custom attribute key was invalid. Not removing from attribute array.";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String removeFromCustomAttributeArray$lambda$54(String str) {
        return AbstractC1475a.a("Failed to remove custom attribute with key '", str, "'.");
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String removeFromSubscriptionGroup$lambda$30() {
        return "Invalid subscription group ID: subscription group ID is required to be non-null and non-empty. Not removing user from subscription group.";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String removeFromSubscriptionGroup$lambda$32(String str) {
        return AbstractC1484j.a("Failed to remove user from subscription group ", str);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String setCountry$lambda$19() {
        return "Invalid country parameter: country is required to be non-blank. Not setting country.";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String setCountry$lambda$20(String str) {
        return AbstractC1484j.a("Failed to set country to: ", str);
    }

    public static /* synthetic */ boolean setCustomAttribute$default(BrazeUser brazeUser, String str, Object obj, boolean z, int i, Object obj2) {
        if ((i & 4) != 0) {
            z = false;
        }
        return brazeUser.setCustomAttribute(str, obj, z);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String setCustomAttribute$lambda$70() {
        return "Custom attribute key cannot be null.";
    }

    private static final String setCustomAttribute$lambda$73$lambda$71(String str, Object obj) {
        return "Could not add unsupported custom attribute value with key: " + str + " and value: " + obj;
    }

    private static final String setCustomAttribute$lambda$73$lambda$72(String str, Object obj) {
        return "Could not build NestedCustomAttributeEvent for key " + str + " and " + obj;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String setCustomAttributeArray$lambda$55(String str) {
        return AbstractC1475a.a("Failed to set custom attribute array with key: '", str, "'.");
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String setCustomUserAttribute$lambda$43(String str) {
        return AbstractC1476b.a("Failed to set custom boolean attribute ", str, '.');
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String setCustomUserAttribute$lambda$44(String str) {
        return AbstractC1476b.a("Failed to set custom integer attribute ", str, '.');
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String setCustomUserAttribute$lambda$47(String str) {
        return AbstractC1476b.a("Failed to set custom string attribute ", str, '.');
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String setCustomUserAttribute$lambda$48(String str) {
        return AbstractC1476b.a("Failed to set custom double attribute ", str, '.');
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String setCustomUserAttribute$lambda$49(String str, JSONObject jSONObject) {
        StringBuilder sbY = android.support.v4.media.session.a.y("Failed to set custom json attribute ", str, " with value \n");
        sbY.append(JsonUtils.getPrettyPrintedString(jSONObject));
        sbY.append('.');
        return sbY.toString();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String setDateOfBirth$lambda$18(int i, Month month, int i2) {
        return "Failed to set date of birth to: " + i + '-' + month.getValue() + '-' + i2;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String setEmail$lambda$12() {
        return "Invalid email parameter: email is required to be non-empty. Not setting email.";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String setEmail$lambda$15$lambda$14(String str) {
        return AbstractC1484j.a("Email address is not valid: ", str);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String setEmail$lambda$16(String str) {
        return AbstractC1484j.a("Failed to set email to: ", str);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String setEmailNotificationSubscriptionType$lambda$25(NotificationSubscriptionType notificationSubscriptionType) {
        return "Failed to set email notification subscription to: " + notificationSubscriptionType;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String setFirstName$lambda$8() {
        return "Invalid first name parameter: first name is required to be non-empty. Not setting first name.";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String setFirstName$lambda$9(String str) {
        return AbstractC1484j.a("Failed to set first name to: ", str);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String setGender$lambda$17(Gender gender) {
        return "Failed to set gender to: " + gender;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String setHomeCity$lambda$21() {
        return "Invalid home city parameter: home city is required to be non-blank. Not setting home city.";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String setHomeCity$lambda$22(String str) {
        return AbstractC1484j.a("Failed to set home city to: ", str);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String setLanguage$lambda$23() {
        return "Invalid language parameter: language is required to be non-empty. Not setting language.";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String setLanguage$lambda$24(String str) {
        return AbstractC1484j.a("Failed to set language to: ", str);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String setLastName$lambda$10() {
        return "Invalid last name parameter: last name is required to be non-empty. Not setting last name.";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String setLastName$lambda$11(String str) {
        return AbstractC1484j.a("Failed to set last name to: ", str);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String setLineId$lambda$38() {
        return "Invalid LINE ID parameter: LINE ID is required to be non-empty or null. Not setting LINE ID.";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String setLineId$lambda$41$lambda$40(String str) {
        return AbstractC1484j.a("LINE ID is longer than 33 characters: Failed to set LINE ID: ", str);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String setLineId$lambda$42(String str) {
        return AbstractC1484j.a("Failed to set LINE ID to: ", str);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String setLocationCustomAttribute$lambda$63() {
        return "Custom location attribute key was invalid. Not setting attribute.";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String setLocationCustomAttribute$lambda$64(double d, double d2) {
        return "Cannot set custom location attribute due with invalid latitude '" + d + " and longitude '" + d2 + '\'';
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String setLocationCustomAttribute$lambda$66(String str, double d, double d2) {
        return "Failed to set custom location attribute with key '" + str + "' and latitude '" + d + "' and longitude '" + d2 + '\'';
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String setPhoneNumber$lambda$33() {
        return "Invalid phone number parameter: phone number is required to be non-empty. Not setting phone number.";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String setPhoneNumber$lambda$36$lambda$35(String str) {
        return AbstractC1484j.a("Phone number contains invalid characters (allowed are digits, spaces, or any of the following +.-()): ", str);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String setPhoneNumber$lambda$37(String str) {
        return AbstractC1484j.a("Failed to set phone number to: ", str);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String setPushNotificationSubscriptionType$lambda$26(NotificationSubscriptionType notificationSubscriptionType) {
        return "Failed to set push notification subscription to: " + notificationSubscriptionType;
    }

    public final boolean addAlias(String alias, String label) {
        BrazeUser brazeUser;
        com.braze.models.i iVarS;
        Intrinsics.checkNotNullParameter(alias, "alias");
        Intrinsics.checkNotNullParameter(label, "label");
        if (StringsKt.O(alias)) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new M(26), 6, (Object) null);
            return false;
        }
        if (StringsKt.O(label)) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new M(27), 6, (Object) null);
            return false;
        }
        try {
            iVarS = com.braze.models.outgoing.event.b.g.s(alias, label);
        } catch (Exception e) {
            e = e;
            brazeUser = this;
        }
        if (iVarS == null) {
            return false;
        }
        brazeUser = this;
        try {
            return ((C1500m) brazeUser.brazeManager).a(iVarS);
        } catch (Exception e2) {
            e = e2;
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) brazeUser, BrazeLogger.Priority.E, (Throwable) e, false, (Function0) new androidx.navigation.internal.l(alias, 27), 4, (Object) null);
            return false;
        }
    }

    public final boolean addToCustomAttributeArray(String key, String value) {
        Intrinsics.checkNotNullParameter(key, "key");
        Intrinsics.checkNotNullParameter(value, "value");
        try {
        } catch (Exception e) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.W, (Throwable) e, false, (Function0) new androidx.navigation.internal.l(key, 21), 4, (Object) null);
        }
        if (!com.braze.support.d.a(key, this.serverConfigStorageProvider.e())) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new M(22), 6, (Object) null);
            return false;
        }
        if (com.braze.support.d.c(value)) {
            com.braze.models.i iVarA = com.braze.models.outgoing.event.b.g.a(ValidationUtils.ensureBrazeFieldLength(key), ValidationUtils.ensureBrazeFieldLength(value));
            if (iVarA != null) {
                return ((C1500m) this.brazeManager).a(iVarA);
            }
        }
        return false;
    }

    public final boolean addToSubscriptionGroup(String subscriptionGroupId) {
        BrazeUser brazeUser;
        Intrinsics.checkNotNullParameter(subscriptionGroupId, "subscriptionGroupId");
        try {
            if (StringsKt.O(subscriptionGroupId)) {
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new M(17), 6, (Object) null);
                return false;
            }
            com.braze.models.i iVarA = com.braze.models.outgoing.event.b.g.a(subscriptionGroupId, com.braze.enums.h.a);
            if (iVarA == null) {
                return true;
            }
            brazeUser = this;
            try {
                ((C1500m) brazeUser.brazeManager).a(iVarA);
                return true;
            } catch (Exception e) {
                e = e;
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) brazeUser, BrazeLogger.Priority.W, (Throwable) e, false, (Function0) new androidx.navigation.internal.l(subscriptionGroupId, 16), 4, (Object) null);
                return false;
            }
        } catch (Exception e2) {
            e = e2;
            brazeUser = this;
        }
    }

    public final String getUserId() {
        ReentrantLock reentrantLock = this.userIdLock;
        reentrantLock.lock();
        try {
            return this.internalUserId;
        } finally {
            reentrantLock.unlock();
        }
    }

    public final boolean incrementCustomUserAttribute(String key, int i) {
        Intrinsics.checkNotNullParameter(key, "key");
        try {
            if (!com.braze.support.d.a(key, this.serverConfigStorageProvider.e())) {
                return false;
            }
            com.braze.models.i iVarA = com.braze.models.outgoing.event.b.g.a(ValidationUtils.ensureBrazeFieldLength(key), i);
            if (iVarA == null) {
                return false;
            }
            return ((C1500m) this.brazeManager).a(iVarA);
        } catch (Exception e) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.W, (Throwable) e, false, (Function0) new P(key, i, 0), 4, (Object) null);
            return false;
        }
    }

    public final boolean removeFromCustomAttributeArray(String key, String value) {
        Intrinsics.checkNotNullParameter(key, "key");
        Intrinsics.checkNotNullParameter(value, "value");
        try {
        } catch (Exception e) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.W, (Throwable) e, false, (Function0) new androidx.navigation.internal.l(key, 15), 4, (Object) null);
        }
        if (!com.braze.support.d.a(key, this.serverConfigStorageProvider.e())) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new Y(1), 6, (Object) null);
            return false;
        }
        if (com.braze.support.d.c(value)) {
            com.braze.models.i iVarQ = com.braze.models.outgoing.event.b.g.q(ValidationUtils.ensureBrazeFieldLength(key), ValidationUtils.ensureBrazeFieldLength(value));
            if (iVarQ != null) {
                return ((C1500m) this.brazeManager).a(iVarQ);
            }
        }
        return false;
    }

    public final boolean removeFromSubscriptionGroup(String subscriptionGroupId) {
        BrazeUser brazeUser;
        Intrinsics.checkNotNullParameter(subscriptionGroupId, "subscriptionGroupId");
        try {
            if (StringsKt.O(subscriptionGroupId)) {
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new M(28), 6, (Object) null);
                return false;
            }
            com.braze.models.i iVarA = com.braze.models.outgoing.event.b.g.a(subscriptionGroupId, com.braze.enums.h.b);
            if (iVarA == null) {
                return true;
            }
            brazeUser = this;
            try {
                ((C1500m) brazeUser.brazeManager).a(iVarA);
                return true;
            } catch (Exception e) {
                e = e;
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) brazeUser, BrazeLogger.Priority.W, (Throwable) e, false, (Function0) new W(subscriptionGroupId, 3), 4, (Object) null);
                return false;
            }
        } catch (Exception e2) {
            e = e2;
            brazeUser = this;
        }
    }

    public final boolean setCountry(String str) {
        BrazeUser brazeUser;
        if (str == null) {
            brazeUser = this;
            kotlinx.coroutines.E.A(com.braze.coroutine.f.a, null, null, new d0(brazeUser, str, null), 3);
            return true;
        }
        try {
            if (StringsKt.O(str)) {
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new M(18), 6, (Object) null);
                return false;
            }
            brazeUser = this;
            try {
                kotlinx.coroutines.E.A(com.braze.coroutine.f.a, null, null, new d0(brazeUser, str, null), 3);
                return true;
            } catch (Exception e) {
                e = e;
            }
        } catch (Exception e2) {
            e = e2;
            brazeUser = this;
        }
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) brazeUser, BrazeLogger.Priority.W, (Throwable) e, false, (Function0) new androidx.navigation.internal.l(str, 17), 4, (Object) null);
        return false;
    }

    public final boolean setCustomAttribute(String key, Object value, boolean z) {
        Intrinsics.checkNotNullParameter(key, "key");
        Intrinsics.checkNotNullParameter(value, "value");
        if (!com.braze.support.d.a(key, this.serverConfigStorageProvider.e())) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new M(29), 6, (Object) null);
            return false;
        }
        String strEnsureBrazeFieldLength = ValidationUtils.ensureBrazeFieldLength(key);
        Object objA = com.braze.support.d.a.a(value, 0);
        if (objA == null) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new X(key, 0, value), 6, (Object) null);
            return false;
        }
        if (!(objA instanceof JSONObject) || !z) {
            kotlinx.coroutines.E.A(com.braze.coroutine.f.a, null, null, new e0(this, strEnsureBrazeFieldLength, objA, null), 3);
            return true;
        }
        com.braze.models.i iVarA = com.braze.models.outgoing.event.b.g.a(strEnsureBrazeFieldLength, (JSONObject) objA);
        if (iVarA != null) {
            return ((C1500m) this.brazeManager).a(iVarA);
        }
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new X(strEnsureBrazeFieldLength, 1, objA), 6, (Object) null);
        return false;
    }

    public final boolean setCustomAttributeArray(String key, String[] values) {
        Intrinsics.checkNotNullParameter(key, "key");
        Intrinsics.checkNotNullParameter(values, "values");
        try {
            if (com.braze.support.d.a(key, this.serverConfigStorageProvider.e())) {
                String strEnsureBrazeFieldLength = ValidationUtils.ensureBrazeFieldLength(key);
                Intrinsics.checkNotNullParameter(values, "values");
                ArrayList arrayList = new ArrayList(values.length);
                for (String str : values) {
                    arrayList.add(ValidationUtils.ensureBrazeFieldLength(str));
                }
                com.braze.models.i iVarA = com.braze.models.outgoing.event.b.g.a(strEnsureBrazeFieldLength, (String[]) arrayList.toArray(new String[0]));
                if (iVarA != null) {
                    return ((C1500m) this.brazeManager).a(iVarA);
                }
            }
        } catch (Exception e) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.W, (Throwable) e, false, (Function0) new W(key, 4), 4, (Object) null);
        }
        return false;
    }

    public final boolean setCustomUserAttribute(String key, boolean z) {
        String str;
        Intrinsics.checkNotNullParameter(key, "key");
        try {
            str = key;
        } catch (Exception e) {
            e = e;
            str = key;
        }
        try {
            return setCustomAttribute$default(this, str, Boolean.valueOf(z), false, 4, null);
        } catch (Exception e2) {
            e = e2;
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.W, (Throwable) e, false, (Function0) new W(str, 2), 4, (Object) null);
            return false;
        }
    }

    public final boolean setDateOfBirth(int i, Month month, int i2) {
        int i3;
        int i4;
        Intrinsics.checkNotNullParameter(month, "month");
        try {
            i3 = i;
            i4 = i2;
        } catch (Exception e) {
            e = e;
            i3 = i;
            i4 = i2;
        }
        try {
            kotlinx.coroutines.E.A(com.braze.coroutine.f.a, null, null, new f0(this, DateTimeUtils.formatDate$default(DateTimeUtils.createDate$default(i3, month.getValue(), i4, 0, 0, 0, 56, null), BrazeDateFormat.SHORT, null, 2, null), null), 3);
            return true;
        } catch (Exception e2) {
            e = e2;
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.W, (Throwable) e, false, (Function0) new U(i3, month, i4), 4, (Object) null);
            return false;
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:13:0x0029 A[Catch: Exception -> 0x0020, TryCatch #0 {Exception -> 0x0020, blocks: (B:4:0x0006, B:6:0x000c, B:13:0x0029, B:18:0x0037, B:25:0x004c, B:28:0x0052, B:29:0x0055, B:32:0x0062, B:35:0x0069, B:37:0x0081), top: B:45:0x0006 }] */
    /* JADX WARN: Removed duplicated region for block: B:30:0x005f  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean setEmail(java.lang.String r21) {
        /*
            r20 = this;
            r1 = r21
            r2 = 0
            r0 = 1
            if (r1 == 0) goto L26
            boolean r3 = kotlin.text.StringsKt.O(r1)     // Catch: java.lang.Exception -> L20
            if (r3 != r0) goto L26
            com.braze.support.BrazeLogger r4 = com.braze.support.BrazeLogger.INSTANCE     // Catch: java.lang.Exception -> L20
            com.braze.support.BrazeLogger$Priority r6 = com.braze.support.BrazeLogger.Priority.W     // Catch: java.lang.Exception -> L20
            com.braze.Y r9 = new com.braze.Y     // Catch: java.lang.Exception -> L20
            r0 = 0
            r9.<init>(r0)     // Catch: java.lang.Exception -> L20
            r7 = 0
            r8 = 0
            r10 = 6
            r11 = 0
            r5 = r20
            com.braze.support.BrazeLogger.brazelog$default(r4, r5, r6, r7, r8, r9, r10, r11)     // Catch: java.lang.Exception -> L20
            return r2
        L20:
            r0 = move-exception
            r13 = r20
        L23:
            r15 = r0
            goto L91
        L26:
            r3 = 0
            if (r1 == 0) goto L5f
            int r4 = r1.length()     // Catch: java.lang.Exception -> L20
            int r4 = r4 - r0
            r5 = r2
            r6 = r5
        L30:
            if (r5 > r4) goto L55
            if (r6 != 0) goto L36
            r7 = r5
            goto L37
        L36:
            r7 = r4
        L37:
            char r7 = r1.charAt(r7)     // Catch: java.lang.Exception -> L20
            r8 = 32
            int r7 = kotlin.jvm.internal.Intrinsics.g(r7, r8)     // Catch: java.lang.Exception -> L20
            if (r7 > 0) goto L45
            r7 = r0
            goto L46
        L45:
            r7 = r2
        L46:
            if (r6 != 0) goto L4f
            if (r7 != 0) goto L4c
            r6 = r0
            goto L30
        L4c:
            int r5 = r5 + 1
            goto L30
        L4f:
            if (r7 != 0) goto L52
            goto L55
        L52:
            int r4 = r4 + (-1)
            goto L30
        L55:
            int r4 = r4 + r0
            java.lang.CharSequence r4 = r1.subSequence(r5, r4)     // Catch: java.lang.Exception -> L20
            java.lang.String r4 = r4.toString()     // Catch: java.lang.Exception -> L20
            goto L60
        L5f:
            r4 = r3
        L60:
            if (r4 == 0) goto L81
            boolean r5 = com.braze.support.ValidationUtils.isValidEmailAddress(r4)     // Catch: java.lang.Exception -> L20
            if (r5 == 0) goto L69
            goto L81
        L69:
            com.braze.support.BrazeLogger r12 = com.braze.support.BrazeLogger.INSTANCE     // Catch: java.lang.Exception -> L20
            com.braze.W r0 = new com.braze.W     // Catch: java.lang.Exception -> L20
            r3 = 5
            r0.<init>(r1, r3)     // Catch: java.lang.Exception -> L20
            r15 = 0
            r16 = 0
            r18 = 7
            r19 = 0
            r14 = 0
            r13 = r20
            r17 = r0
            com.braze.support.BrazeLogger.brazelog$default(r12, r13, r14, r15, r16, r17, r18, r19)     // Catch: java.lang.Exception -> L20
            return r2
        L81:
            com.braze.coroutine.f r5 = com.braze.coroutine.f.a     // Catch: java.lang.Exception -> L20
            com.braze.g0 r6 = new com.braze.g0     // Catch: java.lang.Exception -> L20
            r13 = r20
            r6.<init>(r13, r4, r3)     // Catch: java.lang.Exception -> L8f
            r4 = 3
            kotlinx.coroutines.E.A(r5, r3, r3, r6, r4)     // Catch: java.lang.Exception -> L8f
            return r0
        L8f:
            r0 = move-exception
            goto L23
        L91:
            com.braze.support.BrazeLogger r12 = com.braze.support.BrazeLogger.INSTANCE
            com.braze.support.BrazeLogger$Priority r14 = com.braze.support.BrazeLogger.Priority.W
            com.braze.W r0 = new com.braze.W
            r3 = 6
            r0.<init>(r1, r3)
            r19 = 0
            r16 = 0
            r18 = 4
            r17 = r0
            com.braze.support.BrazeLogger.brazelog$default(r12, r13, r14, r15, r16, r17, r18, r19)
            return r2
        */
        throw new UnsupportedOperationException("Method not decompiled: com.braze.BrazeUser.setEmail(java.lang.String):boolean");
    }

    public final boolean setEmailNotificationSubscriptionType(NotificationSubscriptionType emailNotificationSubscriptionType) {
        Intrinsics.checkNotNullParameter(emailNotificationSubscriptionType, "emailNotificationSubscriptionType");
        try {
            kotlinx.coroutines.E.A(com.braze.coroutine.f.a, null, null, new h0(this, emailNotificationSubscriptionType, null), 3);
            return true;
        } catch (Exception e) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.W, (Throwable) e, false, (Function0) new T(emailNotificationSubscriptionType, 0), 4, (Object) null);
            return false;
        }
    }

    public final boolean setFirstName(String str) {
        BrazeUser brazeUser;
        if (str == null) {
            brazeUser = this;
            kotlinx.coroutines.E.A(com.braze.coroutine.f.a, null, null, new i0(brazeUser, str, null), 3);
            return true;
        }
        try {
            if (StringsKt.O(str)) {
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new M(21), 6, (Object) null);
                return false;
            }
            brazeUser = this;
            try {
                kotlinx.coroutines.E.A(com.braze.coroutine.f.a, null, null, new i0(brazeUser, str, null), 3);
                return true;
            } catch (Exception e) {
                e = e;
            }
        } catch (Exception e2) {
            e = e2;
            brazeUser = this;
        }
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) brazeUser, BrazeLogger.Priority.W, (Throwable) e, false, (Function0) new androidx.navigation.internal.l(str, 20), 4, (Object) null);
        return false;
    }

    public final boolean setGender(Gender gender) {
        Intrinsics.checkNotNullParameter(gender, "gender");
        try {
            kotlinx.coroutines.E.A(com.braze.coroutine.f.a, null, null, new j0(this, gender, null), 3);
            return true;
        } catch (Exception e) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.W, (Throwable) e, false, (Function0) new C1247h(gender, 11), 4, (Object) null);
            return false;
        }
    }

    public final boolean setHomeCity(String str) {
        BrazeUser brazeUser;
        if (str == null) {
            brazeUser = this;
            kotlinx.coroutines.E.A(com.braze.coroutine.f.a, null, null, new k0(brazeUser, str, null), 3);
            return true;
        }
        try {
            if (StringsKt.O(str)) {
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new M(24), 6, (Object) null);
                return false;
            }
            brazeUser = this;
            try {
                kotlinx.coroutines.E.A(com.braze.coroutine.f.a, null, null, new k0(brazeUser, str, null), 3);
                return true;
            } catch (Exception e) {
                e = e;
            }
        } catch (Exception e2) {
            e = e2;
            brazeUser = this;
        }
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) brazeUser, BrazeLogger.Priority.W, (Throwable) e, false, (Function0) new androidx.navigation.internal.l(str, 24), 4, (Object) null);
        return false;
    }

    public final boolean setLanguage(String str) {
        BrazeUser brazeUser;
        if (str == null) {
            brazeUser = this;
            kotlinx.coroutines.E.A(com.braze.coroutine.f.a, null, null, new l0(brazeUser, str, null), 3);
            return true;
        }
        try {
            if (StringsKt.O(str)) {
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new M(20), 6, (Object) null);
                return false;
            }
            brazeUser = this;
            try {
                kotlinx.coroutines.E.A(com.braze.coroutine.f.a, null, null, new l0(brazeUser, str, null), 3);
                return true;
            } catch (Exception e) {
                e = e;
            }
        } catch (Exception e2) {
            e = e2;
            brazeUser = this;
        }
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) brazeUser, BrazeLogger.Priority.W, (Throwable) e, false, (Function0) new androidx.navigation.internal.l(str, 19), 4, (Object) null);
        return false;
    }

    public final boolean setLastName(String str) {
        BrazeUser brazeUser;
        if (str == null) {
            brazeUser = this;
            kotlinx.coroutines.E.A(com.braze.coroutine.f.a, null, null, new m0(brazeUser, str, null), 3);
            return true;
        }
        try {
            if (StringsKt.O(str)) {
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new M(23), 6, (Object) null);
                return false;
            }
            brazeUser = this;
            try {
                kotlinx.coroutines.E.A(com.braze.coroutine.f.a, null, null, new m0(brazeUser, str, null), 3);
                return true;
            } catch (Exception e) {
                e = e;
            }
        } catch (Exception e2) {
            e = e2;
            brazeUser = this;
        }
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) brazeUser, BrazeLogger.Priority.W, (Throwable) e, false, (Function0) new androidx.navigation.internal.l(str, 22), 4, (Object) null);
        return false;
    }

    /* JADX WARN: Removed duplicated region for block: B:13:0x002a A[Catch: Exception -> 0x0021, TryCatch #1 {Exception -> 0x0021, blocks: (B:4:0x0006, B:6:0x000c, B:13:0x002a, B:18:0x0038, B:25:0x004d, B:28:0x0053, B:29:0x0056, B:32:0x0063, B:35:0x006a, B:37:0x0084), top: B:47:0x0006 }] */
    /* JADX WARN: Removed duplicated region for block: B:30:0x0060  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean setLineId(java.lang.String r21) {
        /*
            r20 = this;
            r1 = r21
            r2 = 0
            r0 = 1
            if (r1 == 0) goto L27
            boolean r3 = kotlin.text.StringsKt.O(r1)     // Catch: java.lang.Exception -> L21
            if (r3 != r0) goto L27
            com.braze.support.BrazeLogger r4 = com.braze.support.BrazeLogger.INSTANCE     // Catch: java.lang.Exception -> L21
            com.braze.support.BrazeLogger$Priority r6 = com.braze.support.BrazeLogger.Priority.W     // Catch: java.lang.Exception -> L21
            com.braze.M r9 = new com.braze.M     // Catch: java.lang.Exception -> L21
            r0 = 25
            r9.<init>(r0)     // Catch: java.lang.Exception -> L21
            r7 = 0
            r8 = 0
            r10 = 6
            r11 = 0
            r5 = r20
            com.braze.support.BrazeLogger.brazelog$default(r4, r5, r6, r7, r8, r9, r10, r11)     // Catch: java.lang.Exception -> L21
            return r2
        L21:
            r0 = move-exception
            r13 = r20
        L24:
            r15 = r0
            goto L94
        L27:
            r3 = 0
            if (r1 == 0) goto L60
            int r4 = r1.length()     // Catch: java.lang.Exception -> L21
            int r4 = r4 - r0
            r5 = r2
            r6 = r5
        L31:
            if (r5 > r4) goto L56
            if (r6 != 0) goto L37
            r7 = r5
            goto L38
        L37:
            r7 = r4
        L38:
            char r7 = r1.charAt(r7)     // Catch: java.lang.Exception -> L21
            r8 = 32
            int r7 = kotlin.jvm.internal.Intrinsics.g(r7, r8)     // Catch: java.lang.Exception -> L21
            if (r7 > 0) goto L46
            r7 = r0
            goto L47
        L46:
            r7 = r2
        L47:
            if (r6 != 0) goto L50
            if (r7 != 0) goto L4d
            r6 = r0
            goto L31
        L4d:
            int r5 = r5 + 1
            goto L31
        L50:
            if (r7 != 0) goto L53
            goto L56
        L53:
            int r4 = r4 + (-1)
            goto L31
        L56:
            int r4 = r4 + r0
            java.lang.CharSequence r4 = r1.subSequence(r5, r4)     // Catch: java.lang.Exception -> L21
            java.lang.String r4 = r4.toString()     // Catch: java.lang.Exception -> L21
            goto L61
        L60:
            r4 = r3
        L61:
            if (r4 == 0) goto L84
            boolean r5 = com.braze.support.ValidationUtils.isValidLineId(r4)     // Catch: java.lang.Exception -> L21
            if (r5 == 0) goto L6a
            goto L84
        L6a:
            com.braze.support.BrazeLogger r12 = com.braze.support.BrazeLogger.INSTANCE     // Catch: java.lang.Exception -> L21
            com.braze.support.BrazeLogger$Priority r14 = com.braze.support.BrazeLogger.Priority.W     // Catch: java.lang.Exception -> L21
            androidx.navigation.internal.l r0 = new androidx.navigation.internal.l     // Catch: java.lang.Exception -> L21
            r3 = 25
            r0.<init>(r4, r3)     // Catch: java.lang.Exception -> L21
            r15 = 0
            r16 = 0
            r18 = 6
            r19 = 0
            r13 = r20
            r17 = r0
            com.braze.support.BrazeLogger.brazelog$default(r12, r13, r14, r15, r16, r17, r18, r19)     // Catch: java.lang.Exception -> L21
            return r2
        L84:
            com.braze.coroutine.f r5 = com.braze.coroutine.f.a     // Catch: java.lang.Exception -> L21
            com.braze.n0 r6 = new com.braze.n0     // Catch: java.lang.Exception -> L21
            r13 = r20
            r6.<init>(r13, r4, r3)     // Catch: java.lang.Exception -> L92
            r4 = 3
            kotlinx.coroutines.E.A(r5, r3, r3, r6, r4)     // Catch: java.lang.Exception -> L92
            return r0
        L92:
            r0 = move-exception
            goto L24
        L94:
            com.braze.support.BrazeLogger r12 = com.braze.support.BrazeLogger.INSTANCE
            com.braze.support.BrazeLogger$Priority r14 = com.braze.support.BrazeLogger.Priority.W
            androidx.navigation.internal.l r0 = new androidx.navigation.internal.l
            r3 = 26
            r0.<init>(r1, r3)
            r19 = 0
            r16 = 0
            r18 = 4
            r17 = r0
            com.braze.support.BrazeLogger.brazelog$default(r12, r13, r14, r15, r16, r17, r18, r19)
            return r2
        */
        throw new UnsupportedOperationException("Method not decompiled: com.braze.BrazeUser.setLineId(java.lang.String):boolean");
    }

    public final void setLocationCustomAttribute(String key, final double d, final double d2) {
        Intrinsics.checkNotNullParameter(key, "key");
        try {
            if (!com.braze.support.d.a(key, this.serverConfigStorageProvider.e())) {
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new M(19), 6, (Object) null);
                return;
            }
            if (ValidationUtils.isValidLocation(d, d2)) {
                com.braze.models.i iVarA = com.braze.models.outgoing.event.b.g.a(ValidationUtils.ensureBrazeFieldLength(key), d, d2);
                if (iVarA != null) {
                    ((C1500m) this.brazeManager).a(iVarA);
                    return;
                }
                return;
            }
            try {
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.W, (Throwable) null, false, new Function0() { // from class: com.braze.Q
                    @Override // kotlin.jvm.functions.Function0
                    public final Object invoke() {
                        return BrazeUser.setLocationCustomAttribute$lambda$64(d, d2);
                    }
                }, 6, (Object) null);
            } catch (Exception e) {
                e = e;
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.W, (Throwable) e, false, (Function0) new S(key, d, d2, 0), 4, (Object) null);
            }
        } catch (Exception e2) {
            e = e2;
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:13:0x002a A[Catch: Exception -> 0x0021, TryCatch #1 {Exception -> 0x0021, blocks: (B:4:0x0006, B:6:0x000c, B:13:0x002a, B:18:0x0038, B:25:0x004d, B:28:0x0053, B:29:0x0056, B:32:0x0063, B:35:0x006a, B:37:0x0084), top: B:47:0x0006 }] */
    /* JADX WARN: Removed duplicated region for block: B:30:0x0060  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean setPhoneNumber(java.lang.String r21) {
        /*
            r20 = this;
            r1 = r21
            r2 = 0
            r0 = 1
            if (r1 == 0) goto L27
            boolean r3 = kotlin.text.StringsKt.O(r1)     // Catch: java.lang.Exception -> L21
            if (r3 != r0) goto L27
            com.braze.support.BrazeLogger r4 = com.braze.support.BrazeLogger.INSTANCE     // Catch: java.lang.Exception -> L21
            com.braze.support.BrazeLogger$Priority r6 = com.braze.support.BrazeLogger.Priority.W     // Catch: java.lang.Exception -> L21
            com.braze.M r9 = new com.braze.M     // Catch: java.lang.Exception -> L21
            r0 = 16
            r9.<init>(r0)     // Catch: java.lang.Exception -> L21
            r7 = 0
            r8 = 0
            r10 = 6
            r11 = 0
            r5 = r20
            com.braze.support.BrazeLogger.brazelog$default(r4, r5, r6, r7, r8, r9, r10, r11)     // Catch: java.lang.Exception -> L21
            return r2
        L21:
            r0 = move-exception
            r13 = r20
        L24:
            r15 = r0
            goto L94
        L27:
            r3 = 0
            if (r1 == 0) goto L60
            int r4 = r1.length()     // Catch: java.lang.Exception -> L21
            int r4 = r4 - r0
            r5 = r2
            r6 = r5
        L31:
            if (r5 > r4) goto L56
            if (r6 != 0) goto L37
            r7 = r5
            goto L38
        L37:
            r7 = r4
        L38:
            char r7 = r1.charAt(r7)     // Catch: java.lang.Exception -> L21
            r8 = 32
            int r7 = kotlin.jvm.internal.Intrinsics.g(r7, r8)     // Catch: java.lang.Exception -> L21
            if (r7 > 0) goto L46
            r7 = r0
            goto L47
        L46:
            r7 = r2
        L47:
            if (r6 != 0) goto L50
            if (r7 != 0) goto L4d
            r6 = r0
            goto L31
        L4d:
            int r5 = r5 + 1
            goto L31
        L50:
            if (r7 != 0) goto L53
            goto L56
        L53:
            int r4 = r4 + (-1)
            goto L31
        L56:
            int r4 = r4 + r0
            java.lang.CharSequence r4 = r1.subSequence(r5, r4)     // Catch: java.lang.Exception -> L21
            java.lang.String r4 = r4.toString()     // Catch: java.lang.Exception -> L21
            goto L61
        L60:
            r4 = r3
        L61:
            if (r4 == 0) goto L84
            boolean r5 = com.braze.support.ValidationUtils.isValidPhoneNumber(r4)     // Catch: java.lang.Exception -> L21
            if (r5 == 0) goto L6a
            goto L84
        L6a:
            com.braze.support.BrazeLogger r12 = com.braze.support.BrazeLogger.INSTANCE     // Catch: java.lang.Exception -> L21
            com.braze.support.BrazeLogger$Priority r14 = com.braze.support.BrazeLogger.Priority.W     // Catch: java.lang.Exception -> L21
            androidx.navigation.internal.l r0 = new androidx.navigation.internal.l     // Catch: java.lang.Exception -> L21
            r3 = 18
            r0.<init>(r4, r3)     // Catch: java.lang.Exception -> L21
            r15 = 0
            r16 = 0
            r18 = 6
            r19 = 0
            r13 = r20
            r17 = r0
            com.braze.support.BrazeLogger.brazelog$default(r12, r13, r14, r15, r16, r17, r18, r19)     // Catch: java.lang.Exception -> L21
            return r2
        L84:
            com.braze.coroutine.f r5 = com.braze.coroutine.f.a     // Catch: java.lang.Exception -> L21
            com.braze.o0 r6 = new com.braze.o0     // Catch: java.lang.Exception -> L21
            r13 = r20
            r6.<init>(r13, r4, r3)     // Catch: java.lang.Exception -> L92
            r4 = 3
            kotlinx.coroutines.E.A(r5, r3, r3, r6, r4)     // Catch: java.lang.Exception -> L92
            return r0
        L92:
            r0 = move-exception
            goto L24
        L94:
            com.braze.support.BrazeLogger r12 = com.braze.support.BrazeLogger.INSTANCE
            com.braze.support.BrazeLogger$Priority r14 = com.braze.support.BrazeLogger.Priority.W
            androidx.navigation.internal.l r0 = new androidx.navigation.internal.l
            r3 = 23
            r0.<init>(r1, r3)
            r19 = 0
            r16 = 0
            r18 = 4
            r17 = r0
            com.braze.support.BrazeLogger.brazelog$default(r12, r13, r14, r15, r16, r17, r18, r19)
            return r2
        */
        throw new UnsupportedOperationException("Method not decompiled: com.braze.BrazeUser.setPhoneNumber(java.lang.String):boolean");
    }

    public final boolean setPushNotificationSubscriptionType(NotificationSubscriptionType pushNotificationSubscriptionType) {
        Intrinsics.checkNotNullParameter(pushNotificationSubscriptionType, "pushNotificationSubscriptionType");
        try {
            kotlinx.coroutines.E.A(com.braze.coroutine.f.a, null, null, new p0(this, pushNotificationSubscriptionType, null), 3);
            return true;
        } catch (Exception e) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.W, (Throwable) e, false, (Function0) new T(pushNotificationSubscriptionType, 1), 4, (Object) null);
            return false;
        }
    }

    public final void setUserId(String userId) {
        Intrinsics.checkNotNullParameter(userId, "userId");
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.V, (Throwable) null, false, (Function0) new W(userId, 1), 6, (Object) null);
        ReentrantLock reentrantLock = this.userIdLock;
        reentrantLock.lock();
        try {
            if (!Intrinsics.b(this.internalUserId, "") && !Intrinsics.b(this.internalUserId, userId)) {
                throw new IllegalArgumentException(("setExternalId can not be used to change the external ID of a UserCache from a non-empty value to a new value. Was: [" + this.internalUserId + "], tried to change to: [" + userId + ']').toString());
            }
            this.internalUserId = userId;
            kotlinx.coroutines.E.A(com.braze.coroutine.f.a, null, null, new r0(this, userId, null), 3);
            reentrantLock.unlock();
        } catch (Throwable th) {
            reentrantLock.unlock();
            throw th;
        }
    }

    public final boolean setCustomUserAttribute(String key, int i) {
        String str;
        Intrinsics.checkNotNullParameter(key, "key");
        try {
            str = key;
        } catch (Exception e) {
            e = e;
            str = key;
        }
        try {
            return setCustomAttribute$default(this, str, Integer.valueOf(i), false, 4, null);
        } catch (Exception e2) {
            e = e2;
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.W, (Throwable) e, false, (Function0) new W(str, 0), 4, (Object) null);
            return false;
        }
    }

    public final boolean setCustomUserAttribute(String key, String value) {
        Intrinsics.checkNotNullParameter(key, "key");
        Intrinsics.checkNotNullParameter(value, "value");
        try {
            return setCustomAttribute$default(this, key, value, false, 4, null);
        } catch (Exception e) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.W, (Throwable) e, false, (Function0) new androidx.navigation.internal.l(key, 28), 4, (Object) null);
            return false;
        }
    }

    public final boolean setCustomUserAttribute(String key, double d) {
        String str;
        Intrinsics.checkNotNullParameter(key, "key");
        try {
            str = key;
        } catch (Exception e) {
            e = e;
            str = key;
        }
        try {
            return setCustomAttribute$default(this, str, Double.valueOf(d), false, 4, null);
        } catch (Exception e2) {
            e = e2;
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.W, (Throwable) e, false, (Function0) new androidx.navigation.internal.l(str, 29), 4, (Object) null);
            return false;
        }
    }

    public final boolean setCustomUserAttribute(String key, JSONObject value, boolean z) {
        Intrinsics.checkNotNullParameter(key, "key");
        Intrinsics.checkNotNullParameter(value, "value");
        try {
            return setCustomAttribute(key, value, z);
        } catch (Exception e) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.W, (Throwable) e, false, (Function0) new V(0, key, value), 4, (Object) null);
            return false;
        }
    }
}

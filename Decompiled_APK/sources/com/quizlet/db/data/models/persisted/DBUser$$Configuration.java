package com.quizlet.db.data.models.persisted;

import com.j256.ormlite.field.DatabaseFieldConfig;
import com.j256.ormlite.table.DatabaseTableConfig;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.db.data.models.persisted.fields.BaseDBModelFields;
import com.quizlet.db.data.models.persisted.fields.DBUserFields;
import java.util.ArrayList;
import java.util.List;

/* loaded from: classes2.dex */
public final class DBUser$$Configuration {
    public static List<DatabaseFieldConfig> getFieldConfigs() {
        ArrayList arrayList = new ArrayList();
        DatabaseFieldConfig databaseFieldConfigE = AbstractC4178x.e("id", "id", true, 2, arrayList);
        AbstractC4178x.q(databaseFieldConfigE, DBUserFields.Names.OBFUSCATED_USER_ID, DBUserFields.Names.OBFUSCATED_USER_ID, 2);
        DatabaseFieldConfig databaseFieldConfigF = AbstractC4178x.f(arrayList, databaseFieldConfigE, "localId", "localGeneratedId", 2);
        AbstractC4178x.q(databaseFieldConfigF, "username", "username", 2);
        arrayList.add(databaseFieldConfigF);
        DatabaseFieldConfig databaseFieldConfig = new DatabaseFieldConfig();
        databaseFieldConfig.setFieldName("timestamp");
        databaseFieldConfig.setMaxForeignAutoRefreshLevel(2);
        arrayList.add(databaseFieldConfig);
        DatabaseFieldConfig databaseFieldConfig2 = new DatabaseFieldConfig();
        databaseFieldConfig2.setFieldName("_imageUrl");
        DatabaseFieldConfig databaseFieldConfigC = AbstractC4178x.c(databaseFieldConfig2, 2, arrayList, databaseFieldConfig2, "userUpgradeType");
        DatabaseFieldConfig databaseFieldConfigT = AbstractC4178x.t(databaseFieldConfigC, 2, arrayList, databaseFieldConfigC, DBUserFields.Names.USER_UPGRADE_TYPE);
        DatabaseFieldConfig databaseFieldConfigD = AbstractC4178x.d(databaseFieldConfigT, "isLocked", 2, arrayList, databaseFieldConfigT);
        DatabaseFieldConfig databaseFieldConfigD2 = AbstractC4178x.d(databaseFieldConfigD, "birthYear", 2, arrayList, databaseFieldConfigD);
        DatabaseFieldConfig databaseFieldConfigD3 = AbstractC4178x.d(databaseFieldConfigD2, "birthMonth", 2, arrayList, databaseFieldConfigD2);
        DatabaseFieldConfig databaseFieldConfigD4 = AbstractC4178x.d(databaseFieldConfigD3, "birthDay", 2, arrayList, databaseFieldConfigD3);
        DatabaseFieldConfig databaseFieldConfigD5 = AbstractC4178x.d(databaseFieldConfigD4, "isConfirmed", 2, arrayList, databaseFieldConfigD4);
        DatabaseFieldConfig databaseFieldConfigD6 = AbstractC4178x.d(databaseFieldConfigD5, "mobileLocale", 2, arrayList, databaseFieldConfigD5);
        DatabaseFieldConfig databaseFieldConfigD7 = AbstractC4178x.d(databaseFieldConfigD6, "userLocalePreference", 2, arrayList, databaseFieldConfigD6);
        AbstractC4178x.q(databaseFieldConfigD7, "selfIdentifiedUserType", DBUserFields.Names.SELF_IDENTIFIED_USER_TYPE, 2);
        arrayList.add(databaseFieldConfigD7);
        DatabaseFieldConfig databaseFieldConfig3 = new DatabaseFieldConfig();
        databaseFieldConfig3.setFieldName("email");
        databaseFieldConfig3.setMaxForeignAutoRefreshLevel(2);
        arrayList.add(databaseFieldConfig3);
        DatabaseFieldConfig databaseFieldConfig4 = new DatabaseFieldConfig();
        databaseFieldConfig4.setFieldName("hasPassword");
        DatabaseFieldConfig databaseFieldConfigT2 = AbstractC4178x.t(databaseFieldConfig4, 2, arrayList, databaseFieldConfig4, DBUserFields.Names.HAS_PASSWORD);
        AbstractC4178x.q(databaseFieldConfigT2, "hasFacebook", DBUserFields.Names.HAS_FACEBOOK, 2);
        DatabaseFieldConfig databaseFieldConfigF2 = AbstractC4178x.f(arrayList, databaseFieldConfigT2, "hasGoogle", DBUserFields.Names.HAS_GOOGLE, 2);
        AbstractC4178x.q(databaseFieldConfigF2, "isConfirmationRequired", DBUserFields.Names.IS_CONFIRMATION_REQUIRED, 2);
        DatabaseFieldConfig databaseFieldConfigF3 = AbstractC4178x.f(arrayList, databaseFieldConfigF2, "canChangeUsername", DBUserFields.Names.CAN_CHANGE_USERNAME, 2);
        AbstractC4178x.q(databaseFieldConfigF3, "isUnderAge", DBUserFields.Names.IS_UNDER_AGE, 2);
        DatabaseFieldConfig databaseFieldConfigF4 = AbstractC4178x.f(arrayList, databaseFieldConfigF3, "isUnderAgeForAds", DBUserFields.Names.IS_UNDER_AGE_FOR_ADS, 2);
        AbstractC4178x.q(databaseFieldConfigF4, DBUserFields.Names.PROFILE_IMAGE_ID, DBUserFields.Names.PROFILE_IMAGE_ID, 2);
        DatabaseFieldConfig databaseFieldConfigF5 = AbstractC4178x.f(arrayList, databaseFieldConfigF4, DBUserFields.Names.NEEDS_CHILD_DIRECTED_TREATMENT, DBUserFields.Names.NEEDS_CHILD_DIRECTED_TREATMENT, 2);
        AbstractC4178x.q(databaseFieldConfigF5, DBUserFields.Names.TIME_ZONE, DBUserFields.Names.TIME_ZONE, 2);
        DatabaseFieldConfig databaseFieldConfigF6 = AbstractC4178x.f(arrayList, databaseFieldConfigF5, "setSrsNotificationTimeSec", DBUserFields.Names.NOTIFICATION_TIME, 2);
        AbstractC4178x.q(databaseFieldConfigF6, DBUserFields.Names.NOTIFICATIONS_ENABLED, DBUserFields.Names.NOTIFICATIONS_ENABLED, 2);
        DatabaseFieldConfig databaseFieldConfigF7 = AbstractC4178x.f(arrayList, databaseFieldConfigF6, DBUserFields.Names.IS_VERIFIED, DBUserFields.Names.IS_VERIFIED, 2);
        AbstractC4178x.q(databaseFieldConfigF7, DBUserFields.Names.IS_ADMIN, DBUserFields.Names.IS_ADMIN, 2);
        DatabaseFieldConfig databaseFieldConfigF8 = AbstractC4178x.f(arrayList, databaseFieldConfigF7, DBUserFields.Names.IS_ELIGIBLE_FOR_FREE_TRIAL, DBUserFields.Names.IS_ELIGIBLE_FOR_FREE_TRIAL, 2);
        AbstractC4178x.q(databaseFieldConfigF8, "hasOptedIntoFreeOfflinePromo", DBUserFields.Names.HAS_OPTED_IN_FOR_OFFLINE_PROMO, 2);
        DatabaseFieldConfig databaseFieldConfigF9 = AbstractC4178x.f(arrayList, databaseFieldConfigF8, DBUserFields.Names.IS_SELF_LEARNER, DBUserFields.Names.IS_SELF_LEARNER, 2);
        AbstractC4178x.q(databaseFieldConfigF9, DBUserFields.Names.SIGNUP_COUNTRY_CODE, DBUserFields.Names.SIGNUP_COUNTRY_CODE, 2);
        DatabaseFieldConfig databaseFieldConfigF10 = AbstractC4178x.f(arrayList, databaseFieldConfigF9, DBUserFields.Names.COUNTRY_CODE, DBUserFields.Names.COUNTRY_CODE, 2);
        AbstractC4178x.q(databaseFieldConfigF10, "dirty", "dirty", 2);
        DatabaseFieldConfig databaseFieldConfigF11 = AbstractC4178x.f(arrayList, databaseFieldConfigF10, "isDeleted", "isDeleted", 2);
        AbstractC4178x.q(databaseFieldConfigF11, "lastModified", "lastModified", 2);
        arrayList.add(databaseFieldConfigF11);
        DatabaseFieldConfig databaseFieldConfig5 = new DatabaseFieldConfig();
        databaseFieldConfig5.setFieldName(BaseDBModelFields.Names.CLIENT_TIMESTAMP);
        databaseFieldConfig5.setColumnName(BaseDBModelFields.Names.CLIENT_TIMESTAMP);
        databaseFieldConfig5.setMaxForeignAutoRefreshLevel(2);
        arrayList.add(databaseFieldConfig5);
        return arrayList;
    }

    public static DatabaseTableConfig<DBUser> getTableConfig() {
        DatabaseTableConfig<DBUser> databaseTableConfigG = AbstractC4178x.g(DBUser.class, "user");
        databaseTableConfigG.setFieldConfigs(getFieldConfigs());
        return databaseTableConfigG;
    }
}

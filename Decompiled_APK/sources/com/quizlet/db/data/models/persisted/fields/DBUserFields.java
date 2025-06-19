package com.quizlet.db.data.models.persisted.fields;

import com.quizlet.db.data.models.base.ColumnField;
import com.quizlet.db.data.models.base.ModelField;
import com.quizlet.db.data.models.persisted.DBUser;
import com.quizlet.db.data.models.persisted.base.ModelType;
import com.quizlet.db.data.models.persisted.base.Models;

/* loaded from: classes2.dex */
public class DBUserFields {
    public static final ModelField<DBUser, Long> ID;
    public static final ModelField<DBUser, Long> LOCAL_ID;

    public static final class Names {
        public static final String CAN_CHANGE_USERNAME = "dCanChangeUsername";
        public static final String COUNTRY_CODE = "countryCode";
        public static final String HAS_FACEBOOK = "dHasFacebook";
        public static final String HAS_GOOGLE = "dHasGoogle";
        public static final String HAS_OPTED_IN_FOR_OFFLINE_PROMO = "hasOptedInForOfflinePromo";
        public static final String HAS_PASSWORD = "dHasPassword";
        public static final String ID = "id";
        public static final String IS_ADMIN = "isAdmin";
        public static final String IS_CONFIRMATION_REQUIRED = "dIsConfirmationRequired";
        public static final String IS_ELIGIBLE_FOR_FREE_TRIAL = "isEligibleForFreeTrial";
        public static final String IS_SELF_LEARNER = "isSelfLearner";
        public static final String IS_UNDER_AGE = "dIsUnderAge";
        public static final String IS_UNDER_AGE_FOR_ADS = "dIsUnderAgeForAds";
        public static final String IS_VERIFIED = "isVerified";
        public static final String LOCAL_ID = "localGeneratedId";
        public static final String NEEDS_CHILD_DIRECTED_TREATMENT = "dNeedsChildDirectedTreatment";
        public static final String NOTIFICATIONS_ENABLED = "srsPushNotificationsEnabled";
        public static final String NOTIFICATION_TIME = "srsNotificationTime";
        public static final String OBFUSCATED_USER_ID = "obfuscatedUserId";
        public static final String PROFILE_IMAGE_ID = "profileImageId";
        public static final String SELF_IDENTIFIED_USER_TYPE = "selfIdentifiedTeacherStatus";
        public static final String SIGNUP_COUNTRY_CODE = "signupCountryCode";
        public static final String TIME_ZONE = "timeZone";
        public static final String USERNAME = "username";
        public static final String USER_UPGRADE_TYPE = "type";
    }

    static {
        ModelType<DBUser> modelType = Models.USER;
        LOCAL_ID = new ColumnField<DBUser, Long>(modelType, "localGeneratedId") { // from class: com.quizlet.db.data.models.persisted.fields.DBUserFields.1
            @Override // com.quizlet.db.data.models.base.ModelField
            public Long getValue(DBUser dBUser) {
                return Long.valueOf(dBUser.getLocalId());
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public void setValue(DBUser dBUser, Long l) {
                dBUser.setLocalId(l.longValue());
            }
        };
        ID = new ColumnField<DBUser, Long>(modelType, "id") { // from class: com.quizlet.db.data.models.persisted.fields.DBUserFields.2
            @Override // com.quizlet.db.data.models.base.ModelField
            public Long getValue(DBUser dBUser) {
                return Long.valueOf(dBUser.getId());
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public void setValue(DBUser dBUser, Long l) {
                dBUser.setId(l.longValue());
            }
        };
    }
}

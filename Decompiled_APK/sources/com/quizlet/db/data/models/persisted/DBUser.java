package com.quizlet.db.data.models.persisted;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.j256.ormlite.field.DatabaseField;
import com.j256.ormlite.table.DatabaseTable;
import com.quizlet.db.data.models.base.BaseDBModel;
import com.quizlet.db.data.models.identity.ModelBackedIdentity;
import com.quizlet.db.data.models.identity.ModelIdentity;
import com.quizlet.db.data.models.persisted.base.ModelType;
import com.quizlet.db.data.models.persisted.base.Models;
import com.quizlet.db.data.models.persisted.fields.DBUserFields;
import com.quizlet.quizletandroid.R;

@JsonIgnoreProperties(ignoreUnknown = true)
@DatabaseTable(tableName = "user")
/* loaded from: classes2.dex */
public class DBUser extends BaseDBModel {
    public static final String TABLE_NAME = "user";

    @DatabaseField
    private String _imageUrl;

    @DatabaseField
    private int birthDay;

    @DatabaseField
    private int birthMonth;

    @DatabaseField
    private int birthYear;

    @DatabaseField(columnName = DBUserFields.Names.CAN_CHANGE_USERNAME)
    private boolean canChangeUsername;

    @DatabaseField(columnName = DBUserFields.Names.COUNTRY_CODE)
    private String countryCode;

    @DatabaseField(columnName = DBUserFields.Names.NEEDS_CHILD_DIRECTED_TREATMENT)
    private boolean dNeedsChildDirectedTreatment;

    @DatabaseField
    private String email;

    @DatabaseField(columnName = DBUserFields.Names.HAS_FACEBOOK)
    private boolean hasFacebook;

    @DatabaseField(columnName = DBUserFields.Names.HAS_GOOGLE)
    private boolean hasGoogle;

    @DatabaseField(columnName = DBUserFields.Names.HAS_OPTED_IN_FOR_OFFLINE_PROMO)
    private boolean hasOptedIntoFreeOfflinePromo;

    @DatabaseField(columnName = DBUserFields.Names.HAS_PASSWORD)
    private boolean hasPassword;

    @DatabaseField(columnName = "id", id = true)
    private long id;

    @DatabaseField(columnName = DBUserFields.Names.IS_ADMIN)
    private boolean isAdmin;

    @DatabaseField(columnName = DBUserFields.Names.IS_CONFIRMATION_REQUIRED)
    private boolean isConfirmationRequired;

    @DatabaseField
    private boolean isConfirmed;

    @DatabaseField(columnName = DBUserFields.Names.IS_ELIGIBLE_FOR_FREE_TRIAL)
    private boolean isEligibleForFreeTrial;

    @DatabaseField
    private boolean isLocked;

    @DatabaseField(columnName = DBUserFields.Names.IS_SELF_LEARNER)
    private boolean isSelfLearner;

    @DatabaseField(columnName = DBUserFields.Names.IS_UNDER_AGE)
    private boolean isUnderAge;

    @DatabaseField(columnName = DBUserFields.Names.IS_UNDER_AGE_FOR_ADS)
    private boolean isUnderAgeForAds;

    @DatabaseField(columnName = DBUserFields.Names.IS_VERIFIED)
    private boolean isVerified;

    @DatabaseField(columnName = "localGeneratedId")
    private long localId;

    @DatabaseField
    private String mobileLocale;

    @DatabaseField(columnName = DBUserFields.Names.OBFUSCATED_USER_ID)
    private String obfuscatedUserId;

    @DatabaseField(columnName = DBUserFields.Names.PROFILE_IMAGE_ID)
    private String profileImageId;

    @DatabaseField(columnName = DBUserFields.Names.SELF_IDENTIFIED_USER_TYPE)
    private int selfIdentifiedUserType;

    @DatabaseField(columnName = DBUserFields.Names.NOTIFICATION_TIME)
    private int setSrsNotificationTimeSec;

    @DatabaseField(columnName = DBUserFields.Names.SIGNUP_COUNTRY_CODE)
    private String signupCountryCode;

    @DatabaseField(columnName = DBUserFields.Names.NOTIFICATIONS_ENABLED)
    private boolean srsPushNotificationsEnabled;

    @DatabaseField(columnName = DBUserFields.Names.TIME_ZONE)
    private String timeZone;

    @DatabaseField
    private int timestamp;

    @DatabaseField
    private String userLocalePreference;

    @DatabaseField(columnName = DBUserFields.Names.USER_UPGRADE_TYPE)
    private int userUpgradeType;

    @DatabaseField(columnName = "username")
    private String username;

    @JsonProperty("_canChangeUsername")
    public boolean canChangeUsername() {
        return this.canChangeUsername;
    }

    @JsonProperty("birthDay")
    public int getBirthDay() {
        return this.birthDay;
    }

    @JsonProperty("birthMonth")
    public int getBirthMonth() {
        return this.birthMonth;
    }

    @JsonProperty("birthYear")
    public int getBirthYear() {
        return this.birthYear;
    }

    @JsonProperty(DBUserFields.Names.COUNTRY_CODE)
    public String getCountryCode() {
        return this.countryCode;
    }

    @JsonIgnore
    public int getCreatorBadgeText() {
        return (getUserUpgradeType() == 1 || getUserUpgradeType() == 3) ? R.string.plus : getUserUpgradeType() == 2 ? R.string.teacher : R.string.empty;
    }

    @JsonProperty("email")
    public String getEmail() {
        return this.email;
    }

    @JsonProperty("_hasOptedIntoFreeOfflinePromo")
    public boolean getHasOptedIntoFreeOfflinePromo() {
        return this.hasOptedIntoFreeOfflinePromo;
    }

    @JsonIgnore
    public long getId() {
        return this.id;
    }

    @Override // com.quizlet.db.data.models.base.BaseDBModel, com.quizlet.db.data.models.base.DBModel
    public ModelIdentity<DBUser> getIdentity() {
        return new ModelBackedIdentity(this);
    }

    @JsonProperty("_imageUrl")
    public String getImageUrl() {
        return this._imageUrl;
    }

    @JsonProperty(DBUserFields.Names.IS_ADMIN)
    public boolean getIsAdmin() {
        return this.isAdmin;
    }

    @JsonProperty("isConfirmed")
    public boolean getIsConfirmed() {
        return this.isConfirmed;
    }

    @JsonProperty("_isEligibleForFreeTrial")
    public boolean getIsEligibleForFreeTrial() {
        return this.isEligibleForFreeTrial;
    }

    @JsonProperty("isLocked")
    public boolean getIsLocked() {
        return this.isLocked;
    }

    @JsonProperty(DBUserFields.Names.IS_SELF_LEARNER)
    public boolean getIsSelfLearner() {
        return this.isSelfLearner;
    }

    public boolean getIsUnderAge() {
        return this.isUnderAge;
    }

    public boolean getIsUnderAgeForAds() {
        return this.isUnderAgeForAds;
    }

    @JsonProperty(DBUserFields.Names.IS_VERIFIED)
    public boolean getIsVerified() {
        return this.isVerified;
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    @JsonProperty("id")
    public Long getJsonId() {
        long j = this.id;
        if (j > 0) {
            return Long.valueOf(j);
        }
        return null;
    }

    @Override // com.quizlet.db.data.models.base.BaseDBModel, com.quizlet.db.data.models.base.DBModel
    public long getLocalId() {
        return this.localId;
    }

    @JsonProperty("mobileLocale")
    public String getMobileLocale() {
        return this.mobileLocale;
    }

    @Override // com.quizlet.db.data.models.base.BaseDBModel, com.quizlet.db.data.models.base.DBModel
    public ModelType<DBUser> getModelType() {
        return Models.USER;
    }

    @JsonProperty(DBUserFields.Names.OBFUSCATED_USER_ID)
    public String getObfuscatedUserId() {
        return this.obfuscatedUserId;
    }

    @JsonProperty(DBUserFields.Names.PROFILE_IMAGE_ID)
    public String getProfileImageId() {
        return this.profileImageId;
    }

    @JsonProperty(DBUserFields.Names.SELF_IDENTIFIED_USER_TYPE)
    public int getSelfIdentifiedUserType() {
        return this.selfIdentifiedUserType;
    }

    @JsonProperty(DBUserFields.Names.SIGNUP_COUNTRY_CODE)
    public String getSignupCountryCode() {
        return this.signupCountryCode;
    }

    @JsonProperty(DBUserFields.Names.NOTIFICATION_TIME)
    public int getSrsNotificationTimeSec() {
        return this.setSrsNotificationTimeSec;
    }

    @JsonProperty(DBUserFields.Names.NOTIFICATIONS_ENABLED)
    public boolean getSrsPushNotificationsEnabled() {
        return this.srsPushNotificationsEnabled;
    }

    @JsonProperty(DBUserFields.Names.TIME_ZONE)
    public String getTimeZone() {
        return this.timeZone;
    }

    @JsonProperty("timestamp")
    public int getTimestamp() {
        return this.timestamp;
    }

    @JsonProperty("userLocalePreference")
    public String getUserLocalePreference() {
        return this.userLocalePreference;
    }

    @JsonProperty(DBUserFields.Names.USER_UPGRADE_TYPE)
    public int getUserUpgradeType() {
        return this.userUpgradeType;
    }

    public String getUsername() {
        return this.username;
    }

    @JsonProperty("_hasFacebook")
    public boolean hasFacebook() {
        return this.hasFacebook;
    }

    @JsonProperty("_hasGoogle")
    public boolean hasGoogle() {
        return this.hasGoogle;
    }

    @JsonProperty("_hasPassword")
    public boolean hasPassword() {
        return this.hasPassword;
    }

    @JsonProperty("_isConfirmationRequired")
    public boolean isConfirmationRequired() {
        return this.isConfirmationRequired;
    }

    @JsonProperty("_needsChildDirectedTreatment")
    public boolean needsChildDirectedTreatment() {
        return this.dNeedsChildDirectedTreatment;
    }

    public void setBirthDay(int i) {
        this.birthDay = i;
    }

    public void setBirthMonth(int i) {
        this.birthMonth = i;
    }

    public void setBirthYear(int i) {
        this.birthYear = i;
    }

    public void setCanChangeUsername(boolean z) {
        this.canChangeUsername = z;
    }

    public void setCountryCode(String str) {
        this.countryCode = str;
    }

    public void setEmail(String str) {
        this.email = str;
    }

    public void setHasFacebook(boolean z) {
        this.hasFacebook = z;
    }

    public void setHasGoogle(boolean z) {
        this.hasGoogle = z;
    }

    public void setHasOptedIntoFreeOfflinePromo(boolean z) {
        this.hasOptedIntoFreeOfflinePromo = z;
    }

    public void setHasPassword(boolean z) {
        this.hasPassword = z;
    }

    public void setId(long j) {
        this.id = j;
    }

    public void setImageUrl(String str) {
        this._imageUrl = str;
    }

    public void setIsAdmin(boolean z) {
        this.isAdmin = z;
    }

    public void setIsConfirmationRequired(boolean z) {
        this.isConfirmationRequired = z;
    }

    public void setIsConfirmed(boolean z) {
        this.isConfirmed = z;
    }

    public void setIsEligibleForFreeTrial(boolean z) {
        this.isEligibleForFreeTrial = z;
    }

    public void setIsLocked(boolean z) {
        this.isLocked = z;
    }

    public void setIsSelfLearner(boolean z) {
        this.isSelfLearner = z;
    }

    @JsonProperty("_isUnderAge")
    public void setIsUnderAge(boolean z) {
        this.isUnderAge = z;
    }

    @JsonProperty("_isUnderAgeForAds")
    public void setIsUnderAgeForAds(boolean z) {
        this.isUnderAgeForAds = z;
    }

    public void setIsVerified(boolean z) {
        this.isVerified = z;
    }

    public void setJsonId(Long l) {
        this.id = l.longValue();
    }

    @Override // com.quizlet.db.data.models.base.BaseDBModel, com.quizlet.db.data.models.base.DBModel
    public void setLocalId(long j) {
        this.localId = j;
    }

    public void setMobileLocale(String str) {
        this.mobileLocale = str;
    }

    public void setNeedsChildDirectedTreatment(boolean z) {
        this.dNeedsChildDirectedTreatment = z;
    }

    public void setObfuscatedUserId(String str) {
        this.obfuscatedUserId = str;
    }

    public void setProfileImageId(String str) {
        this.profileImageId = str;
    }

    public void setSelfIdentifiedUserType(int i) {
        this.selfIdentifiedUserType = i;
    }

    public void setSignupCountryCode(String str) {
        this.signupCountryCode = str;
    }

    public void setSrsNotificationTimeSec(int i) {
        this.setSrsNotificationTimeSec = i;
    }

    public void setSrsPushNotificationsEnabled(boolean z) {
        this.srsPushNotificationsEnabled = z;
    }

    public void setTimeZone(String str) {
        this.timeZone = str;
    }

    public void setTimestamp(int i) {
        this.timestamp = i;
    }

    public void setUserLocalePreference(String str) {
        this.userLocalePreference = str;
    }

    public void setUserUpgradeType(int i) {
        this.userUpgradeType = i;
    }

    public void setUsername(String str) {
        this.username = str;
    }
}

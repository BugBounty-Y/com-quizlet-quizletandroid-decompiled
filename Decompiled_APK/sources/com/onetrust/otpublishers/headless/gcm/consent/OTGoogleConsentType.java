package com.onetrust.otpublishers.headless.gcm.consent;

import androidx.annotation.Keep;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Keep
@Metadata
/* loaded from: classes2.dex */
public final class OTGoogleConsentType {

    @NotNull
    private OTGCMConsentStatus adPersonalization;

    @NotNull
    private OTGCMConsentStatus adStorage;

    @NotNull
    private OTGCMConsentStatus adUserData;

    @NotNull
    private OTGCMConsentStatus analyticsStorage;

    @NotNull
    private OTGCMConsentStatus functionalityStorage;

    @NotNull
    private OTGCMConsentStatus personalizationStorage;

    @NotNull
    private OTGCMConsentStatus securityStorage;

    public OTGoogleConsentType() {
        this(null, null, null, null, null, null, null, 127, null);
    }

    public static /* synthetic */ OTGoogleConsentType copy$default(OTGoogleConsentType oTGoogleConsentType, OTGCMConsentStatus oTGCMConsentStatus, OTGCMConsentStatus oTGCMConsentStatus2, OTGCMConsentStatus oTGCMConsentStatus3, OTGCMConsentStatus oTGCMConsentStatus4, OTGCMConsentStatus oTGCMConsentStatus5, OTGCMConsentStatus oTGCMConsentStatus6, OTGCMConsentStatus oTGCMConsentStatus7, int i, Object obj) {
        if ((i & 1) != 0) {
            oTGCMConsentStatus = oTGoogleConsentType.analyticsStorage;
        }
        if ((i & 2) != 0) {
            oTGCMConsentStatus2 = oTGoogleConsentType.adStorage;
        }
        if ((i & 4) != 0) {
            oTGCMConsentStatus3 = oTGoogleConsentType.adUserData;
        }
        if ((i & 8) != 0) {
            oTGCMConsentStatus4 = oTGoogleConsentType.adPersonalization;
        }
        if ((i & 16) != 0) {
            oTGCMConsentStatus5 = oTGoogleConsentType.functionalityStorage;
        }
        if ((i & 32) != 0) {
            oTGCMConsentStatus6 = oTGoogleConsentType.personalizationStorage;
        }
        if ((i & 64) != 0) {
            oTGCMConsentStatus7 = oTGoogleConsentType.securityStorage;
        }
        OTGCMConsentStatus oTGCMConsentStatus8 = oTGCMConsentStatus6;
        OTGCMConsentStatus oTGCMConsentStatus9 = oTGCMConsentStatus7;
        OTGCMConsentStatus oTGCMConsentStatus10 = oTGCMConsentStatus5;
        OTGCMConsentStatus oTGCMConsentStatus11 = oTGCMConsentStatus3;
        return oTGoogleConsentType.copy(oTGCMConsentStatus, oTGCMConsentStatus2, oTGCMConsentStatus11, oTGCMConsentStatus4, oTGCMConsentStatus10, oTGCMConsentStatus8, oTGCMConsentStatus9);
    }

    @NotNull
    public final OTGCMConsentStatus component1() {
        return this.analyticsStorage;
    }

    @NotNull
    public final OTGCMConsentStatus component2() {
        return this.adStorage;
    }

    @NotNull
    public final OTGCMConsentStatus component3() {
        return this.adUserData;
    }

    @NotNull
    public final OTGCMConsentStatus component4() {
        return this.adPersonalization;
    }

    @NotNull
    public final OTGCMConsentStatus component5() {
        return this.functionalityStorage;
    }

    @NotNull
    public final OTGCMConsentStatus component6() {
        return this.personalizationStorage;
    }

    @NotNull
    public final OTGCMConsentStatus component7() {
        return this.securityStorage;
    }

    @NotNull
    public final OTGoogleConsentType copy(@NotNull OTGCMConsentStatus analyticsStorage, @NotNull OTGCMConsentStatus adStorage, @NotNull OTGCMConsentStatus adUserData, @NotNull OTGCMConsentStatus adPersonalization, @NotNull OTGCMConsentStatus functionalityStorage, @NotNull OTGCMConsentStatus personalizationStorage, @NotNull OTGCMConsentStatus securityStorage) {
        Intrinsics.checkNotNullParameter(analyticsStorage, "analyticsStorage");
        Intrinsics.checkNotNullParameter(adStorage, "adStorage");
        Intrinsics.checkNotNullParameter(adUserData, "adUserData");
        Intrinsics.checkNotNullParameter(adPersonalization, "adPersonalization");
        Intrinsics.checkNotNullParameter(functionalityStorage, "functionalityStorage");
        Intrinsics.checkNotNullParameter(personalizationStorage, "personalizationStorage");
        Intrinsics.checkNotNullParameter(securityStorage, "securityStorage");
        return new OTGoogleConsentType(analyticsStorage, adStorage, adUserData, adPersonalization, functionalityStorage, personalizationStorage, securityStorage);
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof OTGoogleConsentType)) {
            return false;
        }
        OTGoogleConsentType oTGoogleConsentType = (OTGoogleConsentType) obj;
        return this.analyticsStorage == oTGoogleConsentType.analyticsStorage && this.adStorage == oTGoogleConsentType.adStorage && this.adUserData == oTGoogleConsentType.adUserData && this.adPersonalization == oTGoogleConsentType.adPersonalization && this.functionalityStorage == oTGoogleConsentType.functionalityStorage && this.personalizationStorage == oTGoogleConsentType.personalizationStorage && this.securityStorage == oTGoogleConsentType.securityStorage;
    }

    @NotNull
    public final OTGCMConsentStatus getAdPersonalization() {
        return this.adPersonalization;
    }

    @NotNull
    public final OTGCMConsentStatus getAdStorage() {
        return this.adStorage;
    }

    @NotNull
    public final OTGCMConsentStatus getAdUserData() {
        return this.adUserData;
    }

    @NotNull
    public final OTGCMConsentStatus getAnalyticsStorage() {
        return this.analyticsStorage;
    }

    @NotNull
    public final OTGCMConsentStatus getFunctionalityStorage() {
        return this.functionalityStorage;
    }

    @NotNull
    public final OTGCMConsentStatus getPersonalizationStorage() {
        return this.personalizationStorage;
    }

    @NotNull
    public final OTGCMConsentStatus getSecurityStorage() {
        return this.securityStorage;
    }

    public int hashCode() {
        return this.securityStorage.hashCode() + ((this.personalizationStorage.hashCode() + ((this.functionalityStorage.hashCode() + ((this.adPersonalization.hashCode() + ((this.adUserData.hashCode() + ((this.adStorage.hashCode() + (this.analyticsStorage.hashCode() * 31)) * 31)) * 31)) * 31)) * 31)) * 31);
    }

    public final void setAdPersonalization(@NotNull OTGCMConsentStatus oTGCMConsentStatus) {
        Intrinsics.checkNotNullParameter(oTGCMConsentStatus, "<set-?>");
        this.adPersonalization = oTGCMConsentStatus;
    }

    public final void setAdStorage(@NotNull OTGCMConsentStatus oTGCMConsentStatus) {
        Intrinsics.checkNotNullParameter(oTGCMConsentStatus, "<set-?>");
        this.adStorage = oTGCMConsentStatus;
    }

    public final void setAdUserData(@NotNull OTGCMConsentStatus oTGCMConsentStatus) {
        Intrinsics.checkNotNullParameter(oTGCMConsentStatus, "<set-?>");
        this.adUserData = oTGCMConsentStatus;
    }

    public final void setAnalyticsStorage(@NotNull OTGCMConsentStatus oTGCMConsentStatus) {
        Intrinsics.checkNotNullParameter(oTGCMConsentStatus, "<set-?>");
        this.analyticsStorage = oTGCMConsentStatus;
    }

    public final void setFunctionalityStorage(@NotNull OTGCMConsentStatus oTGCMConsentStatus) {
        Intrinsics.checkNotNullParameter(oTGCMConsentStatus, "<set-?>");
        this.functionalityStorage = oTGCMConsentStatus;
    }

    public final void setPersonalizationStorage(@NotNull OTGCMConsentStatus oTGCMConsentStatus) {
        Intrinsics.checkNotNullParameter(oTGCMConsentStatus, "<set-?>");
        this.personalizationStorage = oTGCMConsentStatus;
    }

    public final void setSecurityStorage(@NotNull OTGCMConsentStatus oTGCMConsentStatus) {
        Intrinsics.checkNotNullParameter(oTGCMConsentStatus, "<set-?>");
        this.securityStorage = oTGCMConsentStatus;
    }

    @NotNull
    public String toString() {
        return "OTGoogleConsentType(analyticsStorage=" + this.analyticsStorage + ", adStorage=" + this.adStorage + ", adUserData=" + this.adUserData + ", adPersonalization=" + this.adPersonalization + ", functionalityStorage=" + this.functionalityStorage + ", personalizationStorage=" + this.personalizationStorage + ", securityStorage=" + this.securityStorage + ')';
    }

    public OTGoogleConsentType(@NotNull OTGCMConsentStatus analyticsStorage, @NotNull OTGCMConsentStatus adStorage, @NotNull OTGCMConsentStatus adUserData, @NotNull OTGCMConsentStatus adPersonalization, @NotNull OTGCMConsentStatus functionalityStorage, @NotNull OTGCMConsentStatus personalizationStorage, @NotNull OTGCMConsentStatus securityStorage) {
        Intrinsics.checkNotNullParameter(analyticsStorage, "analyticsStorage");
        Intrinsics.checkNotNullParameter(adStorage, "adStorage");
        Intrinsics.checkNotNullParameter(adUserData, "adUserData");
        Intrinsics.checkNotNullParameter(adPersonalization, "adPersonalization");
        Intrinsics.checkNotNullParameter(functionalityStorage, "functionalityStorage");
        Intrinsics.checkNotNullParameter(personalizationStorage, "personalizationStorage");
        Intrinsics.checkNotNullParameter(securityStorage, "securityStorage");
        this.analyticsStorage = analyticsStorage;
        this.adStorage = adStorage;
        this.adUserData = adUserData;
        this.adPersonalization = adPersonalization;
        this.functionalityStorage = functionalityStorage;
        this.personalizationStorage = personalizationStorage;
        this.securityStorage = securityStorage;
    }

    public /* synthetic */ OTGoogleConsentType(OTGCMConsentStatus oTGCMConsentStatus, OTGCMConsentStatus oTGCMConsentStatus2, OTGCMConsentStatus oTGCMConsentStatus3, OTGCMConsentStatus oTGCMConsentStatus4, OTGCMConsentStatus oTGCMConsentStatus5, OTGCMConsentStatus oTGCMConsentStatus6, OTGCMConsentStatus oTGCMConsentStatus7, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this((i & 1) != 0 ? OTGCMConsentStatus.UNDEFINED : oTGCMConsentStatus, (i & 2) != 0 ? OTGCMConsentStatus.UNDEFINED : oTGCMConsentStatus2, (i & 4) != 0 ? OTGCMConsentStatus.UNDEFINED : oTGCMConsentStatus3, (i & 8) != 0 ? OTGCMConsentStatus.UNDEFINED : oTGCMConsentStatus4, (i & 16) != 0 ? OTGCMConsentStatus.UNDEFINED : oTGCMConsentStatus5, (i & 32) != 0 ? OTGCMConsentStatus.UNDEFINED : oTGCMConsentStatus6, (i & 64) != 0 ? OTGCMConsentStatus.UNDEFINED : oTGCMConsentStatus7);
    }
}

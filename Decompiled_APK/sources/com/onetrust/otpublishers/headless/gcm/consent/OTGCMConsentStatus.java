package com.onetrust.otpublishers.headless.gcm.consent;

import androidx.annotation.Keep;
import kotlin.Metadata;
import org.jetbrains.annotations.NotNull;

@Keep
@Metadata
/* loaded from: classes2.dex */
public enum OTGCMConsentStatus {
    GRANTED("granted"),
    DENIED("denied"),
    UNDEFINED("undefined"),
    UNASSIGNED("unassigned");


    @NotNull
    private final String status;

    OTGCMConsentStatus(String str) {
        this.status = str;
    }

    @NotNull
    public final String getStatus() {
        return this.status;
    }
}

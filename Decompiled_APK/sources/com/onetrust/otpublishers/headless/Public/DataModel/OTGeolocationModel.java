package com.onetrust.otpublishers.headless.Public.DataModel;

import androidx.annotation.NonNull;

/* loaded from: classes2.dex */
public class OTGeolocationModel {
    public String country;
    public String state;

    @NonNull
    public boolean compareLocation(String str) {
        if (str == null) {
            return false;
        }
        return str.equalsIgnoreCase(this.country) || str.equalsIgnoreCase(this.state);
    }
}

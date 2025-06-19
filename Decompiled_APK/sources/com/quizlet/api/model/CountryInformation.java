package com.quizlet.api.model;

/* loaded from: classes2.dex */
public class CountryInformation {
    private String countryCode;
    private int underAgeCutoff;

    public String getCountryCode() {
        return this.countryCode;
    }

    public int getUnderAgeCutoff() {
        return this.underAgeCutoff;
    }

    public void setCountryCode(String str) {
        this.countryCode = str;
    }

    public void setUnderAgeCutoff(int i) {
        this.underAgeCutoff = i;
    }
}

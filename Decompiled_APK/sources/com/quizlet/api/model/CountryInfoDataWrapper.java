package com.quizlet.api.model;

import com.fasterxml.jackson.annotation.JsonProperty;

/* loaded from: classes2.dex */
public class CountryInfoDataWrapper {
    CountryInformation countryInformation;

    public CountryInformation getCountryInformation() {
        return this.countryInformation;
    }

    @JsonProperty("countryInformation")
    public void setCountryInformation(CountryInformation countryInformation) {
        this.countryInformation = countryInformation;
    }
}

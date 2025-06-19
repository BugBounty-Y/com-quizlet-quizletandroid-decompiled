package com.appsflyer.internal;

import kotlin.Metadata;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes.dex */
public enum AFe1wSDK {
    API("api"),
    RC("rc"),
    DEFAULT("");


    @NotNull
    public final String getCurrencyIso4217Code;

    AFe1wSDK(String str) {
        this.getCurrencyIso4217Code = str;
    }
}

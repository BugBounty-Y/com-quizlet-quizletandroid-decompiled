package com.appsflyer.internal;

import kotlin.Metadata;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes.dex */
public enum AFg1cSDK {
    SDK_LIFECYCLE("SDK Lifecycle"),
    PRIVACY_SANDBOX("Privacy Sandbox"),
    PLAY_INTEGRITY_API("Play Integrity Api"),
    OTHER("Other"),
    HTTP_CLIENT("HTTP Client"),
    QUEUE("Queue"),
    CACHE("Cache"),
    PREFERENCES("Preferences"),
    REMOTE_CONTROL("CFG"),
    DDL("DDL"),
    REFERRER("Referrer"),
    META_REFERRER("Meta Referrer"),
    SAMSUNG_PRELOAD_REFERRER("Samsung Preload Referrer"),
    ADVERTISING_ID("Advertising Id"),
    CROSS_PROMOTION("Cross Promotion"),
    EXCEPTION_MANAGER("Exception Manager"),
    ATTRIBUTION("Attribution"),
    RD("RD"),
    ENGAGEMENT("Engagement"),
    ANTI_FRAUD("Anti Fraud"),
    PUBLIC_API("Public API"),
    AD_REVENUE("Ad Revenue"),
    SDK_SETTERS("Setter"),
    PREDICT("Predict"),
    DEVICE_DATA("Device Data"),
    SECURITY("Security"),
    GENERAL("General"),
    PREINSTALL("Preinstall"),
    UNINSTALL("Uninstall"),
    PURCHASE_VALIDATION("Purchase Validation"),
    DMA("DMA"),
    PROXY("PROXY"),
    AF_EXECUTOR("AF Executor"),
    APP_SET_ID("App set ID");


    @NotNull
    final String getRevenue;

    AFg1cSDK(String str) {
        this.getRevenue = str;
    }
}

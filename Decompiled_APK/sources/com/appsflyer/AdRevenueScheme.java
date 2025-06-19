package com.appsflyer;

import kotlin.Metadata;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes.dex */
public final class AdRevenueScheme {

    @NotNull
    public static final String AD_TYPE = "ad_type";

    @NotNull
    public static final String AD_UNIT = "ad_unit";

    @NotNull
    public static final String COUNTRY = "country";

    @NotNull
    public static final AdRevenueScheme INSTANCE = new AdRevenueScheme();

    @NotNull
    public static final String PLACEMENT = "placement";

    private AdRevenueScheme() {
    }
}

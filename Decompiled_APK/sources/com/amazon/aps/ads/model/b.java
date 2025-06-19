package com.amazon.aps.ads.model;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes.dex */
public final class b {
    public static final /* synthetic */ b[] a = {new b("GOOGLE_AD_MANAGER", 0), new b("ADMOB", 1), new b("AD_GENERATION", 2), new b("UNITY_LEVELPLAY", 3), new b("MAX", 4), new b("NIMBUS", 5), new b("OTHER", 6), new b("CUSTOM_MEDIATION", 7), new b("UNKNOWN", 8)};

    /* JADX INFO: Fake field, exist only in values array */
    b EF5;

    public static b valueOf(String str) {
        return (b) Enum.valueOf(b.class, str);
    }

    public static b[] values() {
        return (b[]) a.clone();
    }
}

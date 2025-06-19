package com.braze.enums;

import com.braze.models.IPutIntoJson;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import kotlin.Metadata;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
@Metadata
/* loaded from: classes.dex */
public final class BrazeSdkMetadata implements IPutIntoJson<String> {
    private static final /* synthetic */ kotlin.enums.a $ENTRIES;
    private static final /* synthetic */ BrazeSdkMetadata[] $VALUES;
    public static final a Companion;
    private final String jsonKey;
    public static final BrazeSdkMetadata ADJUST = new BrazeSdkMetadata("ADJUST", 0, "adj");
    public static final BrazeSdkMetadata AIRBRIDGE = new BrazeSdkMetadata("AIRBRIDGE", 1, "air");
    public static final BrazeSdkMetadata APPSFLYER = new BrazeSdkMetadata("APPSFLYER", 2, "apf");
    public static final BrazeSdkMetadata BLUEDOT = new BrazeSdkMetadata("BLUEDOT", 3, "blt");
    public static final BrazeSdkMetadata BRANCH = new BrazeSdkMetadata("BRANCH", 4, "brc");
    public static final BrazeSdkMetadata CORDOVA = new BrazeSdkMetadata("CORDOVA", 5, "cdva");
    public static final BrazeSdkMetadata EXPO = new BrazeSdkMetadata("EXPO", 6, "expo");
    public static final BrazeSdkMetadata FACTUAL = new BrazeSdkMetadata("FACTUAL", 7, "fct");
    public static final BrazeSdkMetadata FOURSQUARE = new BrazeSdkMetadata("FOURSQUARE", 8, "fsq");
    public static final BrazeSdkMetadata FLUTTER = new BrazeSdkMetadata("FLUTTER", 9, "ft");
    public static final BrazeSdkMetadata GRADLE = new BrazeSdkMetadata("GRADLE", 10, "gd");
    public static final BrazeSdkMetadata GOOGLE = new BrazeSdkMetadata("GOOGLE", 11, "gg");
    public static final BrazeSdkMetadata GIMBAL = new BrazeSdkMetadata("GIMBAL", 12, "gmb");
    public static final BrazeSdkMetadata IONIC = new BrazeSdkMetadata("IONIC", 13, "ionc");
    public static final BrazeSdkMetadata KOCHAVA = new BrazeSdkMetadata("KOCHAVA", 14, "kch");
    public static final BrazeSdkMetadata MANUAL = new BrazeSdkMetadata("MANUAL", 15, "manu");
    public static final BrazeSdkMetadata MPARTICLE = new BrazeSdkMetadata("MPARTICLE", 16, "mp");
    public static final BrazeSdkMetadata NPM = new BrazeSdkMetadata("NPM", 17, "npm");
    public static final BrazeSdkMetadata NATIVESCRIPT = new BrazeSdkMetadata("NATIVESCRIPT", 18, "ns");
    public static final BrazeSdkMetadata NUGET = new BrazeSdkMetadata("NUGET", 19, "nugt");
    public static final BrazeSdkMetadata PUB = new BrazeSdkMetadata("PUB", 20, "pub");
    public static final BrazeSdkMetadata RADAR = new BrazeSdkMetadata("RADAR", 21, "rdr");
    public static final BrazeSdkMetadata REACTNATIVE = new BrazeSdkMetadata("REACTNATIVE", 22, "rn");
    public static final BrazeSdkMetadata REACTNATIVENEWARCH = new BrazeSdkMetadata("REACTNATIVENEWARCH", 23, "rnna");
    public static final BrazeSdkMetadata SEGMENT = new BrazeSdkMetadata("SEGMENT", 24, "sg");
    public static final BrazeSdkMetadata SINGULAR = new BrazeSdkMetadata("SINGULAR", 25, "sng");
    public static final BrazeSdkMetadata SPM = new BrazeSdkMetadata("SPM", 26, "spm");
    public static final BrazeSdkMetadata TEALIUM = new BrazeSdkMetadata("TEALIUM", 27, "tl");
    public static final BrazeSdkMetadata UNREAL = new BrazeSdkMetadata("UNREAL", 28, "un");
    public static final BrazeSdkMetadata UNITY_PACKAGE_MANAGER = new BrazeSdkMetadata("UNITY_PACKAGE_MANAGER", 29, "unpm");
    public static final BrazeSdkMetadata UNITY = new BrazeSdkMetadata("UNITY", 30, "ut");
    public static final BrazeSdkMetadata VIZBEE = new BrazeSdkMetadata("VIZBEE", 31, "vzb");
    public static final BrazeSdkMetadata WEBCDN = new BrazeSdkMetadata("WEBCDN", 32, "wcd");
    public static final BrazeSdkMetadata XAMARIN = new BrazeSdkMetadata("XAMARIN", 33, "xam");

    private static final /* synthetic */ BrazeSdkMetadata[] $values() {
        return new BrazeSdkMetadata[]{ADJUST, AIRBRIDGE, APPSFLYER, BLUEDOT, BRANCH, CORDOVA, EXPO, FACTUAL, FOURSQUARE, FLUTTER, GRADLE, GOOGLE, GIMBAL, IONIC, KOCHAVA, MANUAL, MPARTICLE, NPM, NATIVESCRIPT, NUGET, PUB, RADAR, REACTNATIVE, REACTNATIVENEWARCH, SEGMENT, SINGULAR, SPM, TEALIUM, UNREAL, UNITY_PACKAGE_MANAGER, UNITY, VIZBEE, WEBCDN, XAMARIN};
    }

    static {
        BrazeSdkMetadata[] brazeSdkMetadataArr$values = $values();
        $VALUES = brazeSdkMetadataArr$values;
        $ENTRIES = AbstractC3328d.f(brazeSdkMetadataArr$values);
        Companion = new a();
    }

    private BrazeSdkMetadata(String str, int i, String str2) {
        this.jsonKey = str2;
    }

    public static BrazeSdkMetadata valueOf(String str) {
        return (BrazeSdkMetadata) Enum.valueOf(BrazeSdkMetadata.class, str);
    }

    public static BrazeSdkMetadata[] values() {
        return (BrazeSdkMetadata[]) $VALUES.clone();
    }

    @Override // com.braze.models.IPutIntoJson
    public String forJsonPut() {
        return this.jsonKey;
    }
}

package com.braze.enums;

import com.braze.models.IPutIntoJson;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import kotlin.Metadata;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
@Metadata
/* loaded from: classes.dex */
public final class SdkFlavor implements IPutIntoJson<String> {
    private static final /* synthetic */ kotlin.enums.a $ENTRIES;
    private static final /* synthetic */ SdkFlavor[] $VALUES;
    private final String jsonKey;
    public static final SdkFlavor UNITY = new SdkFlavor("UNITY", 0, "unity");
    public static final SdkFlavor REACT = new SdkFlavor("REACT", 1, "react");
    public static final SdkFlavor CORDOVA = new SdkFlavor("CORDOVA", 2, "cordova");
    public static final SdkFlavor XAMARIN = new SdkFlavor("XAMARIN", 3, "xamarin");
    public static final SdkFlavor FLUTTER = new SdkFlavor("FLUTTER", 4, "flutter");
    public static final SdkFlavor SEGMENT = new SdkFlavor("SEGMENT", 5, "segment");
    public static final SdkFlavor TEALIUM = new SdkFlavor("TEALIUM", 6, "tealium");
    public static final SdkFlavor MPARTICLE = new SdkFlavor("MPARTICLE", 7, "mparticle");

    private static final /* synthetic */ SdkFlavor[] $values() {
        return new SdkFlavor[]{UNITY, REACT, CORDOVA, XAMARIN, FLUTTER, SEGMENT, TEALIUM, MPARTICLE};
    }

    static {
        SdkFlavor[] sdkFlavorArr$values = $values();
        $VALUES = sdkFlavorArr$values;
        $ENTRIES = AbstractC3328d.f(sdkFlavorArr$values);
    }

    private SdkFlavor(String str, int i, String str2) {
        this.jsonKey = str2;
    }

    public static SdkFlavor valueOf(String str) {
        return (SdkFlavor) Enum.valueOf(SdkFlavor.class, str);
    }

    public static SdkFlavor[] values() {
        return (SdkFlavor[]) $VALUES.clone();
    }

    @Override // com.braze.models.IPutIntoJson
    public String forJsonPut() {
        return this.jsonKey;
    }
}

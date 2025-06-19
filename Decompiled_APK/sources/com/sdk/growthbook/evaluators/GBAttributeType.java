package com.sdk.growthbook.evaluators;

import com.amazon.device.ads.DtbDeviceDataRetriever;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import kotlin.Metadata;
import kotlin.enums.a;
import kotlin.jvm.internal.DefaultConstructorMarker;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
@Metadata
/* loaded from: classes3.dex */
public class GBAttributeType {
    private static final /* synthetic */ a $ENTRIES;
    private static final /* synthetic */ GBAttributeType[] $VALUES;
    public static final GBAttributeType GbString = new GBAttributeType("GbString", 0) { // from class: com.sdk.growthbook.evaluators.GBAttributeType.GbString
        {
            DefaultConstructorMarker defaultConstructorMarker = null;
        }

        @Override // java.lang.Enum
        @NotNull
        public String toString() {
            return "string";
        }
    };
    public static final GBAttributeType GbNumber = new GBAttributeType("GbNumber", 1) { // from class: com.sdk.growthbook.evaluators.GBAttributeType.GbNumber
        {
            DefaultConstructorMarker defaultConstructorMarker = null;
        }

        @Override // java.lang.Enum
        @NotNull
        public String toString() {
            return "number";
        }
    };
    public static final GBAttributeType GbBoolean = new GBAttributeType("GbBoolean", 2) { // from class: com.sdk.growthbook.evaluators.GBAttributeType.GbBoolean
        {
            DefaultConstructorMarker defaultConstructorMarker = null;
        }

        @Override // java.lang.Enum
        @NotNull
        public String toString() {
            return "boolean";
        }
    };
    public static final GBAttributeType GbArray = new GBAttributeType("GbArray", 3) { // from class: com.sdk.growthbook.evaluators.GBAttributeType.GbArray
        {
            DefaultConstructorMarker defaultConstructorMarker = null;
        }

        @Override // java.lang.Enum
        @NotNull
        public String toString() {
            return "array";
        }
    };
    public static final GBAttributeType GbObject = new GBAttributeType("GbObject", 4) { // from class: com.sdk.growthbook.evaluators.GBAttributeType.GbObject
        {
            DefaultConstructorMarker defaultConstructorMarker = null;
        }

        @Override // java.lang.Enum
        @NotNull
        public String toString() {
            return "object";
        }
    };
    public static final GBAttributeType GbNull = new GBAttributeType("GbNull", 5) { // from class: com.sdk.growthbook.evaluators.GBAttributeType.GbNull
        {
            DefaultConstructorMarker defaultConstructorMarker = null;
        }

        @Override // java.lang.Enum
        @NotNull
        public String toString() {
            return "null";
        }
    };
    public static final GBAttributeType GbUnknown = new GBAttributeType("GbUnknown", 6) { // from class: com.sdk.growthbook.evaluators.GBAttributeType.GbUnknown
        {
            DefaultConstructorMarker defaultConstructorMarker = null;
        }

        @Override // java.lang.Enum
        @NotNull
        public String toString() {
            return DtbDeviceDataRetriever.ORIENTATION_UNKNOWN;
        }
    };

    private static final /* synthetic */ GBAttributeType[] $values() {
        return new GBAttributeType[]{GbString, GbNumber, GbBoolean, GbArray, GbObject, GbNull, GbUnknown};
    }

    static {
        GBAttributeType[] gBAttributeTypeArr$values = $values();
        $VALUES = gBAttributeTypeArr$values;
        $ENTRIES = AbstractC3328d.f(gBAttributeTypeArr$values);
    }

    public /* synthetic */ GBAttributeType(String str, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this(str, i);
    }

    @NotNull
    public static a getEntries() {
        return $ENTRIES;
    }

    public static GBAttributeType valueOf(String str) {
        return (GBAttributeType) Enum.valueOf(GBAttributeType.class, str);
    }

    public static GBAttributeType[] values() {
        return (GBAttributeType[]) $VALUES.clone();
    }

    private GBAttributeType(String str, int i) {
    }
}

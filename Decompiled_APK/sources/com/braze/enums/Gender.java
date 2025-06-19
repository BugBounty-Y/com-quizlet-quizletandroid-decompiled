package com.braze.enums;

import com.braze.models.IPutIntoJson;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
@Metadata
/* loaded from: classes.dex */
public final class Gender implements IPutIntoJson<String> {
    private static final /* synthetic */ kotlin.enums.a $ENTRIES;
    private static final /* synthetic */ Gender[] $VALUES;
    public static final Companion Companion;
    private final String value;
    public static final Gender MALE = new Gender("MALE", 0, "m");
    public static final Gender FEMALE = new Gender("FEMALE", 1, "f");
    public static final Gender OTHER = new Gender("OTHER", 2, "o");
    public static final Gender UNKNOWN = new Gender("UNKNOWN", 3, "u");
    public static final Gender NOT_APPLICABLE = new Gender("NOT_APPLICABLE", 4, "n");
    public static final Gender PREFER_NOT_TO_SAY = new Gender("PREFER_NOT_TO_SAY", 5, "p");

    @Metadata
    public static final class Companion {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private Companion() {
        }
    }

    private static final /* synthetic */ Gender[] $values() {
        return new Gender[]{MALE, FEMALE, OTHER, UNKNOWN, NOT_APPLICABLE, PREFER_NOT_TO_SAY};
    }

    static {
        Gender[] genderArr$values = $values();
        $VALUES = genderArr$values;
        $ENTRIES = AbstractC3328d.f(genderArr$values);
        Companion = new Companion(null);
    }

    private Gender(String str, int i, String str2) {
        this.value = str2;
    }

    public static Gender valueOf(String str) {
        return (Gender) Enum.valueOf(Gender.class, str);
    }

    public static Gender[] values() {
        return (Gender[]) $VALUES.clone();
    }

    @Override // com.braze.models.IPutIntoJson
    public String forJsonPut() {
        return this.value;
    }
}

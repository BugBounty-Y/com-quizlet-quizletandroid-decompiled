package com.quizlet.utm.sources;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class a implements com.quizlet.utm.b {
    private static final /* synthetic */ kotlin.enums.a $ENTRIES;
    private static final /* synthetic */ a[] $VALUES;
    private final int index;
    public static final a FACEBOOK = new a("FACEBOOK", 0, 1);
    public static final a TWITTER = new a("TWITTER", 1, 2);
    public static final a EMAIL = new a("EMAIL", 2, 3);
    public static final a COPY_LINK = new a("COPY_LINK", 3, 4);
    public static final a REMIND = new a("REMIND", 4, 5);
    public static final a GOOGLE_CLASSROOM = new a("GOOGLE_CLASSROOM", 5, 6);
    public static final a SHARE_SHEET_ANDROID = new a("SHARE_SHEET_ANDROID", 6, 7);
    public static final a SHARE_SHEET_IOS = new a("SHARE_SHEET_IOS", 7, 8);
    public static final a FIREFLY = new a("FIREFLY", 8, 9);
    public static final a STUDY_MODE_EMBED = new a("STUDY_MODE_EMBED", 9, 10);
    public static final a MS_TEAMS = new a("MS_TEAMS", 10, 11);
    public static final a SATCHEL = new a("SATCHEL", 11, 12);

    private static final /* synthetic */ a[] $values() {
        return new a[]{FACEBOOK, TWITTER, EMAIL, COPY_LINK, REMIND, GOOGLE_CLASSROOM, SHARE_SHEET_ANDROID, SHARE_SHEET_IOS, FIREFLY, STUDY_MODE_EMBED, MS_TEAMS, SATCHEL};
    }

    static {
        a[] aVarArr$values = $values();
        $VALUES = aVarArr$values;
        $ENTRIES = AbstractC3328d.f(aVarArr$values);
    }

    private a(String str, int i, int i2) {
        this.index = i2;
    }

    @NotNull
    public static kotlin.enums.a getEntries() {
        return $ENTRIES;
    }

    public static a valueOf(String str) {
        return (a) Enum.valueOf(a.class, str);
    }

    public static a[] values() {
        return (a[]) $VALUES.clone();
    }

    @Override // com.quizlet.utm.b
    public int getIndex() {
        return this.index;
    }
}

package com.quizlet.utm.sources;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import com.quizlet.utm.c;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class b implements c {
    private static final /* synthetic */ kotlin.enums.a $ENTRIES;
    private static final /* synthetic */ b[] $VALUES;

    @NotNull
    public static final a Companion;

    @NotNull
    private final String value;
    public static final b FACEBOOK = new b("FACEBOOK", 0, "facebook");
    public static final b TWITTER = new b("TWITTER", 1, "twitter");
    public static final b EMAIL = new b("EMAIL", 2, "email");
    public static final b COPY_LINK = new b("COPY_LINK", 3, "copy-link");
    public static final b REMIND = new b("REMIND", 4, "remind");
    public static final b GOOGLE_CLASSROOM = new b("GOOGLE_CLASSROOM", 5, "classroom.google.com");
    public static final b SHARE_SHEET_ANDROID = new b("SHARE_SHEET_ANDROID", 6, "share-sheet-android");
    public static final b SHARE_SHEET_IOS = new b("SHARE_SHEET_IOS", 7, "share-sheet-ios");
    public static final b FIREFLY = new b("FIREFLY", 8, "firefly");
    public static final b STUDY_MODE_EMBED = new b("STUDY_MODE_EMBED", 9, "study-mode-embed");
    public static final b MS_TEAMS = new b("MS_TEAMS", 10, "ms-teams");
    public static final b SATCHEL = new b("SATCHEL", 11, "satchel-one");

    public static final class a {
        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public final b fromValue(String str) {
            for (b bVar : b.values()) {
                if (Intrinsics.b(bVar.getValue(), str)) {
                    return bVar;
                }
            }
            return null;
        }

        private a() {
        }
    }

    private static final /* synthetic */ b[] $values() {
        return new b[]{FACEBOOK, TWITTER, EMAIL, COPY_LINK, REMIND, GOOGLE_CLASSROOM, SHARE_SHEET_ANDROID, SHARE_SHEET_IOS, FIREFLY, STUDY_MODE_EMBED, MS_TEAMS, SATCHEL};
    }

    static {
        b[] bVarArr$values = $values();
        $VALUES = bVarArr$values;
        $ENTRIES = AbstractC3328d.f(bVarArr$values);
        Companion = new a(null);
    }

    private b(String str, int i, String str2) {
        this.value = str2;
    }

    @NotNull
    public static kotlin.enums.a getEntries() {
        return $ENTRIES;
    }

    public static b valueOf(String str) {
        return (b) Enum.valueOf(b.class, str);
    }

    public static b[] values() {
        return (b[]) $VALUES.clone();
    }

    @Override // com.quizlet.utm.c
    @NotNull
    public String getValue() {
        return this.value;
    }
}

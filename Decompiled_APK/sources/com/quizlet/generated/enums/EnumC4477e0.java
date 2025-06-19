package com.quizlet.generated.enums;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* renamed from: com.quizlet.generated.enums.e0, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class EnumC4477e0 {
    private static final /* synthetic */ kotlin.enums.a $ENTRIES;
    private static final /* synthetic */ EnumC4477e0[] $VALUES;
    public static final EnumC4477e0 BROKEN_PDF;

    @NotNull
    public static final C4474d0 Companion;
    public static final EnumC4477e0 FILE_SIZE_TOO_LARGE;
    public static final EnumC4477e0 FILE_TYPE_MISMATCH;
    public static final EnumC4477e0 GENERIC_FILE_UPLOAD_ERROR;
    public static final EnumC4477e0 INVALID_YOUTUBE_URL;
    public static final EnumC4477e0 MULTI_FILE_UPLOAD_FILES_INVALID;
    public static final EnumC4477e0 NOT_ENOUGH_CHARACTERS;
    public static final EnumC4477e0 TOO_MANY_CHARACTERS;
    public static final EnumC4477e0 UNABLE_TO_EXTRACT_TEXT;
    public static final EnumC4477e0 UNSUPPORTED_FILE_TYPE;
    public static final EnumC4477e0 UPLOAD_LIMIT_REACHED;

    @NotNull
    private final String value;

    static {
        EnumC4477e0 enumC4477e0 = new EnumC4477e0("FILE_SIZE_TOO_LARGE", 0, "file_size_too_large");
        FILE_SIZE_TOO_LARGE = enumC4477e0;
        EnumC4477e0 enumC4477e02 = new EnumC4477e0("FILE_TYPE_MISMATCH", 1, "file_type_mismatch");
        FILE_TYPE_MISMATCH = enumC4477e02;
        EnumC4477e0 enumC4477e03 = new EnumC4477e0("NOT_ENOUGH_CHARACTERS", 2, "not_enough_characters");
        NOT_ENOUGH_CHARACTERS = enumC4477e03;
        EnumC4477e0 enumC4477e04 = new EnumC4477e0("TOO_MANY_CHARACTERS", 3, "too_many_characters");
        TOO_MANY_CHARACTERS = enumC4477e04;
        EnumC4477e0 enumC4477e05 = new EnumC4477e0("UNABLE_TO_EXTRACT_TEXT", 4, "unable_to_extract_text");
        UNABLE_TO_EXTRACT_TEXT = enumC4477e05;
        EnumC4477e0 enumC4477e06 = new EnumC4477e0("UNSUPPORTED_FILE_TYPE", 5, "unsupported_file_type");
        UNSUPPORTED_FILE_TYPE = enumC4477e06;
        EnumC4477e0 enumC4477e07 = new EnumC4477e0("INVALID_YOUTUBE_URL", 6, "invalid_youtube_url");
        INVALID_YOUTUBE_URL = enumC4477e07;
        EnumC4477e0 enumC4477e08 = new EnumC4477e0("MULTI_FILE_UPLOAD_FILES_INVALID", 7, "multi_file_upload_files_invalid");
        MULTI_FILE_UPLOAD_FILES_INVALID = enumC4477e08;
        EnumC4477e0 enumC4477e09 = new EnumC4477e0("BROKEN_PDF", 8, "broken_pdf");
        BROKEN_PDF = enumC4477e09;
        EnumC4477e0 enumC4477e010 = new EnumC4477e0("UPLOAD_LIMIT_REACHED", 9, "magic_notes_upload_limit_reached");
        UPLOAD_LIMIT_REACHED = enumC4477e010;
        EnumC4477e0 enumC4477e011 = new EnumC4477e0("GENERIC_FILE_UPLOAD_ERROR", 10, "generic_file_upload_error");
        GENERIC_FILE_UPLOAD_ERROR = enumC4477e011;
        EnumC4477e0[] enumC4477e0Arr = {enumC4477e0, enumC4477e02, enumC4477e03, enumC4477e04, enumC4477e05, enumC4477e06, enumC4477e07, enumC4477e08, enumC4477e09, enumC4477e010, enumC4477e011};
        $VALUES = enumC4477e0Arr;
        $ENTRIES = AbstractC3328d.f(enumC4477e0Arr);
        Companion = new C4474d0();
    }

    public EnumC4477e0(String str, int i, String str2) {
        this.value = str2;
    }

    public static EnumC4477e0 valueOf(String str) {
        return (EnumC4477e0) Enum.valueOf(EnumC4477e0.class, str);
    }

    public static EnumC4477e0[] values() {
        return (EnumC4477e0[]) $VALUES.clone();
    }

    public final String a() {
        return this.value;
    }
}

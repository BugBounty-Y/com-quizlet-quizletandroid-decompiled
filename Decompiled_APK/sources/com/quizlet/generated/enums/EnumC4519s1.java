package com.quizlet.generated.enums;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* renamed from: com.quizlet.generated.enums.s1, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class EnumC4519s1 {
    private static final /* synthetic */ kotlin.enums.a $ENTRIES;
    private static final /* synthetic */ EnumC4519s1[] $VALUES;
    public static final EnumC4519s1 CLICK;
    public static final EnumC4519s1 CLICK_HIDE_THIS_SET;
    public static final EnumC4519s1 CLICK_SAVE_TO_CLASS;
    public static final EnumC4519s1 CLICK_SAVE_TO_FOLDER;
    public static final EnumC4519s1 CONTAINER_PAGE_VIEW;

    @NotNull
    public static final C4516r1 Companion;
    public static final EnumC4519s1 IMPRESSION;
    public static final EnumC4519s1 PREVIEW;
    public static final EnumC4519s1 PRE_STUDY_PROMPT;
    public static final EnumC4519s1 REJECT;
    public static final EnumC4519s1 SAVE;

    @NotNull
    private final String value;

    static {
        EnumC4519s1 enumC4519s1 = new EnumC4519s1("CLICK", 0, "click");
        CLICK = enumC4519s1;
        EnumC4519s1 enumC4519s12 = new EnumC4519s1("CLICK_HIDE_THIS_SET", 1, "click_hide_this_set");
        CLICK_HIDE_THIS_SET = enumC4519s12;
        EnumC4519s1 enumC4519s13 = new EnumC4519s1("CLICK_SAVE_TO_CLASS", 2, "click_save_to_class");
        CLICK_SAVE_TO_CLASS = enumC4519s13;
        EnumC4519s1 enumC4519s14 = new EnumC4519s1("CLICK_SAVE_TO_FOLDER", 3, "click_save_to_folder");
        CLICK_SAVE_TO_FOLDER = enumC4519s14;
        EnumC4519s1 enumC4519s15 = new EnumC4519s1("CONTAINER_PAGE_VIEW", 4, "container_page_view");
        CONTAINER_PAGE_VIEW = enumC4519s15;
        EnumC4519s1 enumC4519s16 = new EnumC4519s1("IMPRESSION", 5, "impression");
        IMPRESSION = enumC4519s16;
        EnumC4519s1 enumC4519s17 = new EnumC4519s1("PREVIEW", 6, "preview");
        PREVIEW = enumC4519s17;
        EnumC4519s1 enumC4519s18 = new EnumC4519s1("PRE_STUDY_PROMPT", 7, "pre_study_prompt");
        PRE_STUDY_PROMPT = enumC4519s18;
        EnumC4519s1 enumC4519s19 = new EnumC4519s1("REJECT", 8, "reject");
        REJECT = enumC4519s19;
        EnumC4519s1 enumC4519s110 = new EnumC4519s1("SAVE", 9, "save");
        SAVE = enumC4519s110;
        EnumC4519s1[] enumC4519s1Arr = {enumC4519s1, enumC4519s12, enumC4519s13, enumC4519s14, enumC4519s15, enumC4519s16, enumC4519s17, enumC4519s18, enumC4519s19, enumC4519s110};
        $VALUES = enumC4519s1Arr;
        $ENTRIES = AbstractC3328d.f(enumC4519s1Arr);
        Companion = new C4516r1();
    }

    public EnumC4519s1(String str, int i, String str2) {
        this.value = str2;
    }

    public static EnumC4519s1 valueOf(String str) {
        return (EnumC4519s1) Enum.valueOf(EnumC4519s1.class, str);
    }

    public static EnumC4519s1[] values() {
        return (EnumC4519s1[]) $VALUES.clone();
    }

    public final String a() {
        return this.value;
    }
}

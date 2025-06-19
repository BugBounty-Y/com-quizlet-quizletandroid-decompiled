package com.quizlet.edgy.ui.viewmodel;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* renamed from: com.quizlet.edgy.ui.viewmodel.m, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class EnumC4212m {
    public static final EnumC4212m a;
    public static final EnumC4212m b;
    public static final EnumC4212m c;
    public static final EnumC4212m d;
    public static final EnumC4212m e;
    public static final EnumC4212m f;
    public static final EnumC4212m g;
    public static final /* synthetic */ EnumC4212m[] h;

    static {
        EnumC4212m enumC4212m = new EnumC4212m("NULL", 0);
        a = enumC4212m;
        EnumC4212m enumC4212m2 = new EnumC4212m("POPULAR_SCHOOLS_CONCAT_ADAPTER", 1);
        b = enumC4212m2;
        EnumC4212m enumC4212m3 = new EnumC4212m("ADD_SCHOOL_MANUALLY_BUTTON_ADAPTER", 2);
        c = enumC4212m3;
        EnumC4212m enumC4212m4 = new EnumC4212m("ADD_COURSE_MANUALLY_BUTTON_ADAPTER", 3);
        d = enumC4212m4;
        EnumC4212m enumC4212m5 = new EnumC4212m("SCHOOL_CONCAT_ADAPTER", 4);
        e = enumC4212m5;
        EnumC4212m enumC4212m6 = new EnumC4212m("COURSE_CONCAT_ADAPTER", 5);
        f = enumC4212m6;
        EnumC4212m enumC4212m7 = new EnumC4212m("COURSE_SELECTED_ADAPTER", 6);
        g = enumC4212m7;
        EnumC4212m[] enumC4212mArr = {enumC4212m, enumC4212m2, enumC4212m3, enumC4212m4, enumC4212m5, enumC4212m6, enumC4212m7, new EnumC4212m("SEARCH_COURSE_ADAPTER", 7)};
        h = enumC4212mArr;
        AbstractC3328d.f(enumC4212mArr);
    }

    public static EnumC4212m valueOf(String str) {
        return (EnumC4212m) Enum.valueOf(EnumC4212m.class, str);
    }

    public static EnumC4212m[] values() {
        return (EnumC4212m[]) h.clone();
    }
}

package com.quizlet.generated.enums;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class W {
    private static final /* synthetic */ kotlin.enums.a $ENTRIES;
    private static final /* synthetic */ W[] $VALUES;
    public static final W BROWSE;
    public static final W CREATE;

    @NotNull
    public static final V Companion;
    public static final W DISMISS;
    public static final W EXIT;
    public static final W INFO;
    public static final W MLP_REDIRECT;
    public static final W ONBOARDING_CHECKLIST_CLICKED;
    public static final W ONBOARDING_CHECKLIST_SEEN;
    public static final W PUSH_PERMISSIONS;
    public static final W STUDY;
    public static final W SUBMIT;
    public static final W TOGGLE;
    public static final W UPGRADE_GO;
    public static final W UPGRADE_PLUS;
    public static final W UPGRADE_TEACHER;

    @NotNull
    private final String value;

    static {
        W w = new W("BROWSE", 0, "browse");
        BROWSE = w;
        W w2 = new W("CREATE", 1, "create");
        CREATE = w2;
        W w3 = new W("DISMISS", 2, "dismiss");
        DISMISS = w3;
        W w4 = new W("EXIT", 3, "exit");
        EXIT = w4;
        W w5 = new W("INFO", 4, "info");
        INFO = w5;
        W w6 = new W("MLP_REDIRECT", 5, "mlp_redirect");
        MLP_REDIRECT = w6;
        W w7 = new W("PUSH_PERMISSIONS", 6, "push_permissions");
        PUSH_PERMISSIONS = w7;
        W w8 = new W("STUDY", 7, "study");
        STUDY = w8;
        W w9 = new W("SUBMIT", 8, "submit");
        SUBMIT = w9;
        W w10 = new W("TOGGLE", 9, "toggle");
        TOGGLE = w10;
        W w11 = new W("UPGRADE_GO", 10, "upgrade_go");
        UPGRADE_GO = w11;
        W w12 = new W("UPGRADE_PLUS", 11, "upgrade_plus");
        UPGRADE_PLUS = w12;
        W w13 = new W("UPGRADE_TEACHER", 12, "upgrade_teacher");
        UPGRADE_TEACHER = w13;
        W w14 = new W("ONBOARDING_CHECKLIST_SEEN", 13, "onboarding_checklist_seen");
        ONBOARDING_CHECKLIST_SEEN = w14;
        W w15 = new W("ONBOARDING_CHECKLIST_CLICKED", 14, "onboarding_checklist_clicked");
        ONBOARDING_CHECKLIST_CLICKED = w15;
        W[] wArr = {w, w2, w3, w4, w5, w6, w7, w8, w9, w10, w11, w12, w13, w14, w15};
        $VALUES = wArr;
        $ENTRIES = AbstractC3328d.f(wArr);
        Companion = new V();
    }

    public W(String str, int i, String str2) {
        this.value = str2;
    }

    public static W valueOf(String str) {
        return (W) Enum.valueOf(W.class, str);
    }

    public static W[] values() {
        return (W[]) $VALUES.clone();
    }

    public final String a() {
        return this.value;
    }
}

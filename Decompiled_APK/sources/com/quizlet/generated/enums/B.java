package com.quizlet.generated.enums;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class B {
    private static final /* synthetic */ kotlin.enums.a $ENTRIES;
    private static final /* synthetic */ B[] $VALUES;
    public static final B CREATE_NEW_USER_CLICKED;

    @NotNull
    public static final A Companion;
    public static final B EMAIL_CONFIRMATION_SEEN;
    public static final B EMAIL_RESEND_CLICKED;
    public static final B EMAIL_UPDATE_CLICKED;
    public static final B LOGOUT_CLICKED;
    public static final B MAGIC_LINK_CONFIRMATION_SCREEN_SEEN;
    public static final B SEND_MAGIC_LINK_CLICKED;

    @NotNull
    private final String value;

    static {
        B b = new B("EMAIL_CONFIRMATION_SEEN", 0, "email_confirm_screen_seen");
        EMAIL_CONFIRMATION_SEEN = b;
        B b2 = new B("EMAIL_RESEND_CLICKED", 1, "resend_email_click");
        EMAIL_RESEND_CLICKED = b2;
        B b3 = new B("EMAIL_UPDATE_CLICKED", 2, "update_email_click");
        EMAIL_UPDATE_CLICKED = b3;
        B b4 = new B("LOGOUT_CLICKED", 3, "log_out_click");
        LOGOUT_CLICKED = b4;
        B b5 = new B("MAGIC_LINK_CONFIRMATION_SCREEN_SEEN", 4, "magic_link_confirmation_screen_seen");
        MAGIC_LINK_CONFIRMATION_SCREEN_SEEN = b5;
        B b6 = new B("CREATE_NEW_USER_CLICKED", 5, "create_new_user_click");
        CREATE_NEW_USER_CLICKED = b6;
        B b7 = new B("SEND_MAGIC_LINK_CLICKED", 6, "send_magic_link_click");
        SEND_MAGIC_LINK_CLICKED = b7;
        B[] bArr = {b, b2, b3, b4, b5, b6, b7};
        $VALUES = bArr;
        $ENTRIES = AbstractC3328d.f(bArr);
        Companion = new A();
    }

    public B(String str, int i, String str2) {
        this.value = str2;
    }

    public static B valueOf(String str) {
        return (B) Enum.valueOf(B.class, str);
    }

    public static B[] values() {
        return (B[]) $VALUES.clone();
    }

    public final String a() {
        return this.value;
    }
}

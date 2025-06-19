package com.perimeterx.mobile_sdk;

import androidx.annotation.Keep;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
@Keep
@Metadata
/* loaded from: classes2.dex */
public final class PerimeterXErrorCode {
    private static final /* synthetic */ kotlin.enums.a $ENTRIES;
    private static final /* synthetic */ PerimeterXErrorCode[] $VALUES;

    @NotNull
    public static final a Companion;
    public static final PerimeterXErrorCode MISSING_APP_ID = new PerimeterXErrorCode("MISSING_APP_ID", 0);
    public static final PerimeterXErrorCode INVALID_APP_ID = new PerimeterXErrorCode("INVALID_APP_ID", 1);
    public static final PerimeterXErrorCode START_NOT_CALLED_ON_MAIN_THREAD = new PerimeterXErrorCode("START_NOT_CALLED_ON_MAIN_THREAD", 2);
    public static final PerimeterXErrorCode START_CALLED_MORE_THAN_ONCE = new PerimeterXErrorCode("START_CALLED_MORE_THAN_ONCE", 3);
    public static final PerimeterXErrorCode TOKEN_WAS_NOT_GENERATED = new PerimeterXErrorCode("TOKEN_WAS_NOT_GENERATED", 4);
    public static final PerimeterXErrorCode START_WAS_NOT_CALLED = new PerimeterXErrorCode("START_WAS_NOT_CALLED", 5);
    public static final PerimeterXErrorCode INTERNAL_ERROR = new PerimeterXErrorCode("INTERNAL_ERROR", 6);

    private static final /* synthetic */ PerimeterXErrorCode[] $values() {
        return new PerimeterXErrorCode[]{MISSING_APP_ID, INVALID_APP_ID, START_NOT_CALLED_ON_MAIN_THREAD, START_CALLED_MORE_THAN_ONCE, TOKEN_WAS_NOT_GENERATED, START_WAS_NOT_CALLED, INTERNAL_ERROR};
    }

    static {
        PerimeterXErrorCode[] perimeterXErrorCodeArr$values = $values();
        $VALUES = perimeterXErrorCodeArr$values;
        $ENTRIES = AbstractC3328d.f(perimeterXErrorCodeArr$values);
        Companion = new a();
    }

    private PerimeterXErrorCode(String str, int i) {
    }

    @NotNull
    public static kotlin.enums.a getEntries() {
        return $ENTRIES;
    }

    public static PerimeterXErrorCode valueOf(String str) {
        return (PerimeterXErrorCode) Enum.valueOf(PerimeterXErrorCode.class, str);
    }

    public static PerimeterXErrorCode[] values() {
        return (PerimeterXErrorCode[]) $VALUES.clone();
    }

    @NotNull
    public final String message$PerimeterX_release() {
        switch (b.a[ordinal()]) {
            case 1:
                return "missing app id";
            case 2:
                return "invalid app id";
            case 3:
                return "start not called on main thread";
            case 4:
                return "start called more than once";
            case 5:
                return "token was not generated";
            case 6:
                return "start was not called";
            case 7:
                return "internal error";
            default:
                throw new NoWhenBranchMatchedException();
        }
    }
}

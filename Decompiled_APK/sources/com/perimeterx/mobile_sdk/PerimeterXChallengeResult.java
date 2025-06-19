package com.perimeterx.mobile_sdk;

import androidx.annotation.Keep;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import kotlin.Metadata;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
@Keep
@Metadata
/* loaded from: classes2.dex */
public final class PerimeterXChallengeResult {
    private static final /* synthetic */ kotlin.enums.a $ENTRIES;
    private static final /* synthetic */ PerimeterXChallengeResult[] $VALUES;
    public static final PerimeterXChallengeResult SOLVED = new PerimeterXChallengeResult("SOLVED", 0);
    public static final PerimeterXChallengeResult CANCELLED = new PerimeterXChallengeResult("CANCELLED", 1);

    private static final /* synthetic */ PerimeterXChallengeResult[] $values() {
        return new PerimeterXChallengeResult[]{SOLVED, CANCELLED};
    }

    static {
        PerimeterXChallengeResult[] perimeterXChallengeResultArr$values = $values();
        $VALUES = perimeterXChallengeResultArr$values;
        $ENTRIES = AbstractC3328d.f(perimeterXChallengeResultArr$values);
    }

    private PerimeterXChallengeResult(String str, int i) {
    }

    @NotNull
    public static kotlin.enums.a getEntries() {
        return $ENTRIES;
    }

    public static PerimeterXChallengeResult valueOf(String str) {
        return (PerimeterXChallengeResult) Enum.valueOf(PerimeterXChallengeResult.class, str);
    }

    public static PerimeterXChallengeResult[] values() {
        return (PerimeterXChallengeResult[]) $VALUES.clone();
    }
}

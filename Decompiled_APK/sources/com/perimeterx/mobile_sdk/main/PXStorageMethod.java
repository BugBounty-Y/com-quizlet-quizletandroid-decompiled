package com.perimeterx.mobile_sdk.main;

import androidx.annotation.Keep;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import kotlin.Metadata;
import kotlin.enums.a;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
@Keep
@Metadata
/* loaded from: classes2.dex */
public final class PXStorageMethod {
    private static final /* synthetic */ a $ENTRIES;
    private static final /* synthetic */ PXStorageMethod[] $VALUES;
    public static final PXStorageMethod SHARED_PREFERENCES = new PXStorageMethod("SHARED_PREFERENCES", 0);
    public static final PXStorageMethod DATA_STORE = new PXStorageMethod("DATA_STORE", 1);

    private static final /* synthetic */ PXStorageMethod[] $values() {
        return new PXStorageMethod[]{SHARED_PREFERENCES, DATA_STORE};
    }

    static {
        PXStorageMethod[] pXStorageMethodArr$values = $values();
        $VALUES = pXStorageMethodArr$values;
        $ENTRIES = AbstractC3328d.f(pXStorageMethodArr$values);
    }

    private PXStorageMethod(String str, int i) {
    }

    @NotNull
    public static a getEntries() {
        return $ENTRIES;
    }

    public static PXStorageMethod valueOf(String str) {
        return (PXStorageMethod) Enum.valueOf(PXStorageMethod.class, str);
    }

    public static PXStorageMethod[] values() {
        return (PXStorageMethod[]) $VALUES.clone();
    }
}

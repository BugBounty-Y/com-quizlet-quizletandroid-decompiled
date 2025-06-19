package com.braze.ui.inappmessage;

import androidx.annotation.Keep;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import java.util.Locale;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
@Metadata
/* loaded from: classes.dex */
public final class InAppMessageOperation {
    private static final /* synthetic */ kotlin.enums.a $ENTRIES;
    private static final /* synthetic */ InAppMessageOperation[] $VALUES;

    @NotNull
    public static final Companion Companion;
    public static final InAppMessageOperation DISPLAY_NOW = new InAppMessageOperation("DISPLAY_NOW", 0);
    public static final InAppMessageOperation DISPLAY_LATER = new InAppMessageOperation("DISPLAY_LATER", 1);
    public static final InAppMessageOperation DISCARD = new InAppMessageOperation("DISCARD", 2);
    public static final InAppMessageOperation REENQUEUE = new InAppMessageOperation("REENQUEUE", 3);

    @Keep
    @Metadata
    public static final class Companion {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public final InAppMessageOperation fromValue(String str) {
            InAppMessageOperation[] inAppMessageOperationArrValues = InAppMessageOperation.values();
            int length = inAppMessageOperationArrValues.length;
            int i = 0;
            while (true) {
                String upperCase = null;
                if (i >= length) {
                    return null;
                }
                InAppMessageOperation inAppMessageOperation = inAppMessageOperationArrValues[i];
                String strName = inAppMessageOperation.name();
                if (str != null) {
                    Locale US = Locale.US;
                    Intrinsics.checkNotNullExpressionValue(US, "US");
                    upperCase = str.toUpperCase(US);
                    Intrinsics.checkNotNullExpressionValue(upperCase, "toUpperCase(...)");
                }
                if (Intrinsics.b(strName, upperCase)) {
                    return inAppMessageOperation;
                }
                i++;
            }
        }

        private Companion() {
        }
    }

    private static final /* synthetic */ InAppMessageOperation[] $values() {
        return new InAppMessageOperation[]{DISPLAY_NOW, DISPLAY_LATER, DISCARD, REENQUEUE};
    }

    static {
        InAppMessageOperation[] inAppMessageOperationArr$values = $values();
        $VALUES = inAppMessageOperationArr$values;
        $ENTRIES = AbstractC3328d.f(inAppMessageOperationArr$values);
        Companion = new Companion(null);
    }

    private InAppMessageOperation(String str, int i) {
    }

    public static InAppMessageOperation valueOf(String str) {
        return (InAppMessageOperation) Enum.valueOf(InAppMessageOperation.class, str);
    }

    public static InAppMessageOperation[] values() {
        return (InAppMessageOperation[]) $VALUES.clone();
    }
}

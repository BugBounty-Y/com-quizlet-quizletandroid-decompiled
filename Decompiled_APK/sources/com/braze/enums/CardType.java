package com.braze.enums;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
@Metadata
/* loaded from: classes.dex */
public final class CardType {
    private static final /* synthetic */ kotlin.enums.a $ENTRIES;
    private static final /* synthetic */ CardType[] $VALUES;
    public static final Companion Companion;
    public static final CardType IMAGE = new CardType("IMAGE", 0);
    public static final CardType CAPTIONED_IMAGE = new CardType("CAPTIONED_IMAGE", 1);
    public static final CardType DEFAULT = new CardType("DEFAULT", 2);
    public static final CardType SHORT_NEWS = new CardType("SHORT_NEWS", 3);
    public static final CardType TEXT_ANNOUNCEMENT = new CardType("TEXT_ANNOUNCEMENT", 4);
    public static final CardType CONTROL = new CardType("CONTROL", 5);

    @Metadata
    public static final class Companion {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public final CardType fromValue(int i) {
            return CardType.values()[i];
        }

        private Companion() {
        }
    }

    private static final /* synthetic */ CardType[] $values() {
        return new CardType[]{IMAGE, CAPTIONED_IMAGE, DEFAULT, SHORT_NEWS, TEXT_ANNOUNCEMENT, CONTROL};
    }

    static {
        CardType[] cardTypeArr$values = $values();
        $VALUES = cardTypeArr$values;
        $ENTRIES = AbstractC3328d.f(cardTypeArr$values);
        Companion = new Companion(null);
    }

    private CardType(String str, int i) {
    }

    public static CardType valueOf(String str) {
        return (CardType) Enum.valueOf(CardType.class, str);
    }

    public static CardType[] values() {
        return (CardType[]) $VALUES.clone();
    }

    public final int getValue() {
        return ordinal();
    }
}

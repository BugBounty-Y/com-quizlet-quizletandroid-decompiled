package com.braze.enums;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import kotlin.Metadata;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
@Metadata
/* loaded from: classes.dex */
public final class BrazeViewBounds {
    private static final /* synthetic */ kotlin.enums.a $ENTRIES;
    private static final /* synthetic */ BrazeViewBounds[] $VALUES;
    private final int heightDp;
    private final int widthDp;
    public static final BrazeViewBounds NOTIFICATION_EXPANDED_IMAGE = new BrazeViewBounds("NOTIFICATION_EXPANDED_IMAGE", 0, 478, 256);
    public static final BrazeViewBounds NOTIFICATION_INLINE_PUSH_IMAGE = new BrazeViewBounds("NOTIFICATION_INLINE_PUSH_IMAGE", 1, 384, 256);
    public static final BrazeViewBounds NOTIFICATION_LARGE_ICON = new BrazeViewBounds("NOTIFICATION_LARGE_ICON", 2, 64, 64);
    public static final BrazeViewBounds NOTIFICATION_ONE_IMAGE_STORY = new BrazeViewBounds("NOTIFICATION_ONE_IMAGE_STORY", 3, 256, 128);
    public static final BrazeViewBounds BASE_CARD_VIEW = new BrazeViewBounds("BASE_CARD_VIEW", 4, com.google.android.gms.ads.g.MAX_CONTENT_URL_LENGTH, com.google.android.gms.ads.g.MAX_CONTENT_URL_LENGTH);
    public static final BrazeViewBounds IN_APP_MESSAGE_MODAL = new BrazeViewBounds("IN_APP_MESSAGE_MODAL", 5, 580, 580);
    public static final BrazeViewBounds IN_APP_MESSAGE_SLIDEUP = new BrazeViewBounds("IN_APP_MESSAGE_SLIDEUP", 6, 100, 100);
    public static final BrazeViewBounds NO_BOUNDS = new BrazeViewBounds("NO_BOUNDS", 7, 0, 0);

    private static final /* synthetic */ BrazeViewBounds[] $values() {
        return new BrazeViewBounds[]{NOTIFICATION_EXPANDED_IMAGE, NOTIFICATION_INLINE_PUSH_IMAGE, NOTIFICATION_LARGE_ICON, NOTIFICATION_ONE_IMAGE_STORY, BASE_CARD_VIEW, IN_APP_MESSAGE_MODAL, IN_APP_MESSAGE_SLIDEUP, NO_BOUNDS};
    }

    static {
        BrazeViewBounds[] brazeViewBoundsArr$values = $values();
        $VALUES = brazeViewBoundsArr$values;
        $ENTRIES = AbstractC3328d.f(brazeViewBoundsArr$values);
    }

    private BrazeViewBounds(String str, int i, int i2, int i3) {
        this.widthDp = i2;
        this.heightDp = i3;
    }

    public static BrazeViewBounds valueOf(String str) {
        return (BrazeViewBounds) Enum.valueOf(BrazeViewBounds.class, str);
    }

    public static BrazeViewBounds[] values() {
        return (BrazeViewBounds[]) $VALUES.clone();
    }

    public final int getHeightDp() {
        return this.heightDp;
    }

    public final int getWidthDp() {
        return this.widthDp;
    }
}

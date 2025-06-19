package com.amazon.device.ads;

/* loaded from: classes.dex */
enum MraidPlacementType {
    UNKNOWN,
    INLINE,
    INTERSTITIAL;

    /* renamed from: com.amazon.device.ads.MraidPlacementType$1, reason: invalid class name */
    public static /* synthetic */ class AnonymousClass1 {
        static final /* synthetic */ int[] $SwitchMap$com$amazon$device$ads$MraidPlacementType;

        static {
            int[] iArr = new int[MraidPlacementType.values().length];
            $SwitchMap$com$amazon$device$ads$MraidPlacementType = iArr;
            try {
                iArr[MraidPlacementType.UNKNOWN.ordinal()] = 1;
            } catch (NoSuchFieldError unused) {
            }
            try {
                $SwitchMap$com$amazon$device$ads$MraidPlacementType[MraidPlacementType.INLINE.ordinal()] = 2;
            } catch (NoSuchFieldError unused2) {
            }
            try {
                $SwitchMap$com$amazon$device$ads$MraidPlacementType[MraidPlacementType.INTERSTITIAL.ordinal()] = 3;
            } catch (NoSuchFieldError unused3) {
            }
        }
    }

    @Override // java.lang.Enum
    public String toString() {
        int i = AnonymousClass1.$SwitchMap$com$amazon$device$ads$MraidPlacementType[ordinal()];
        return i != 1 ? i != 2 ? i != 3 ? "" : DTBAdSize.AAX_INTERSTITIAL_AD_SIZE : "inline" : DtbDeviceDataRetriever.ORIENTATION_UNKNOWN;
    }
}

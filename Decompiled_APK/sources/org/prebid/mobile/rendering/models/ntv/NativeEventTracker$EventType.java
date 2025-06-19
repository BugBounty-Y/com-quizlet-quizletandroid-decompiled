package org.prebid.mobile.rendering.models.ntv;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class NativeEventTracker$EventType {
    public static final NativeEventTracker$EventType a;
    public static final NativeEventTracker$EventType b;
    public static final /* synthetic */ NativeEventTracker$EventType[] c;

    static {
        NativeEventTracker$EventType nativeEventTracker$EventType = new NativeEventTracker$EventType("IMPRESSION", 0);
        a = nativeEventTracker$EventType;
        NativeEventTracker$EventType nativeEventTracker$EventType2 = new NativeEventTracker$EventType("VIEWABLE_MRC50", 1);
        NativeEventTracker$EventType nativeEventTracker$EventType3 = new NativeEventTracker$EventType("VIEWABLE_MRC100", 2);
        NativeEventTracker$EventType nativeEventTracker$EventType4 = new NativeEventTracker$EventType("VIEWABLE_VIDEO50", 3);
        NativeEventTracker$EventType nativeEventTracker$EventType5 = new NativeEventTracker$EventType("CUSTOM", 4);
        NativeEventTracker$EventType nativeEventTracker$EventType6 = new NativeEventTracker$EventType("OMID", 5);
        b = nativeEventTracker$EventType6;
        c = new NativeEventTracker$EventType[]{nativeEventTracker$EventType, nativeEventTracker$EventType2, nativeEventTracker$EventType3, nativeEventTracker$EventType4, nativeEventTracker$EventType5, nativeEventTracker$EventType6};
    }

    public static NativeEventTracker$EventType valueOf(String str) {
        return (NativeEventTracker$EventType) Enum.valueOf(NativeEventTracker$EventType.class, str);
    }

    public static NativeEventTracker$EventType[] values() {
        return (NativeEventTracker$EventType[]) c.clone();
    }
}

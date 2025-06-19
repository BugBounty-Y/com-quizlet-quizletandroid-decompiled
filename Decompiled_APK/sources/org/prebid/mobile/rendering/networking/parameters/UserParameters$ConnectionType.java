package org.prebid.mobile.rendering.networking.parameters;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class UserParameters$ConnectionType {
    public static final UserParameters$ConnectionType a;
    public static final UserParameters$ConnectionType b;
    public static final UserParameters$ConnectionType c;
    public static final /* synthetic */ UserParameters$ConnectionType[] d;

    static {
        UserParameters$ConnectionType userParameters$ConnectionType = new UserParameters$ConnectionType("OFFLINE", 0);
        a = userParameters$ConnectionType;
        UserParameters$ConnectionType userParameters$ConnectionType2 = new UserParameters$ConnectionType("WIFI", 1);
        b = userParameters$ConnectionType2;
        UserParameters$ConnectionType userParameters$ConnectionType3 = new UserParameters$ConnectionType("CELL", 2);
        c = userParameters$ConnectionType3;
        d = new UserParameters$ConnectionType[]{userParameters$ConnectionType, userParameters$ConnectionType2, userParameters$ConnectionType3};
    }

    public static UserParameters$ConnectionType valueOf(String str) {
        return (UserParameters$ConnectionType) Enum.valueOf(UserParameters$ConnectionType.class, str);
    }

    public static UserParameters$ConnectionType[] values() {
        return (UserParameters$ConnectionType[]) d.clone();
    }
}

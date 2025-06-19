package org.prebid.mobile;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class Host {
    public static final Host b;
    public static final /* synthetic */ Host[] c;
    public String a;

    /* JADX INFO: Fake field, exist only in values array */
    Host EF0;

    static {
        Host host = new Host("CUSTOM", 0);
        host.a = "";
        b = host;
        c = new Host[]{host};
    }

    public static Host valueOf(String str) {
        return (Host) Enum.valueOf(Host.class, str);
    }

    public static Host[] values() {
        return (Host[]) c.clone();
    }
}

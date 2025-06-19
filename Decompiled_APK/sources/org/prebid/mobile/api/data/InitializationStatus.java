package org.prebid.mobile.api.data;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class InitializationStatus {
    public static final InitializationStatus b;
    public static final InitializationStatus c;
    public static final InitializationStatus d;
    public static final /* synthetic */ InitializationStatus[] e;
    public String a;

    static {
        InitializationStatus initializationStatus = new InitializationStatus("SUCCEEDED", 0);
        b = initializationStatus;
        InitializationStatus initializationStatus2 = new InitializationStatus("SERVER_STATUS_WARNING", 1);
        c = initializationStatus2;
        InitializationStatus initializationStatus3 = new InitializationStatus("FAILED", 2);
        d = initializationStatus3;
        e = new InitializationStatus[]{initializationStatus, initializationStatus2, initializationStatus3};
    }

    public static InitializationStatus valueOf(String str) {
        return (InitializationStatus) Enum.valueOf(InitializationStatus.class, str);
    }

    public static InitializationStatus[] values() {
        return (InitializationStatus[]) e.clone();
    }
}

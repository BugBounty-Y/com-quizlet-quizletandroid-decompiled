package com.facebook;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes.dex */
public final class y {
    public static final y a;
    public static final y b;
    public static final y c;
    public static final y d;
    public static final y e;
    public static final y f;
    public static final y g;
    public static final /* synthetic */ y[] h;

    static {
        y yVar = new y("REQUESTS", 0);
        a = yVar;
        y yVar2 = new y("INCLUDE_ACCESS_TOKENS", 1);
        b = yVar2;
        y yVar3 = new y("INCLUDE_RAW_RESPONSES", 2);
        c = yVar3;
        y yVar4 = new y("CACHE", 3);
        y yVar5 = new y("APP_EVENTS", 4);
        d = yVar5;
        y yVar6 = new y("DEVELOPER_ERRORS", 5);
        e = yVar6;
        y yVar7 = new y("GRAPH_API_DEBUG_WARNING", 6);
        f = yVar7;
        y yVar8 = new y("GRAPH_API_DEBUG_INFO", 7);
        g = yVar8;
        h = new y[]{yVar, yVar2, yVar3, yVar4, yVar5, yVar6, yVar7, yVar8};
    }

    public static y valueOf(String str) {
        return (y) Enum.valueOf(y.class, str);
    }

    public static y[] values() {
        return (y[]) h.clone();
    }
}

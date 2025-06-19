package com.snowplowanalytics.snowplow.util;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class a {
    public static final a a;
    public static final /* synthetic */ a[] b;

    /* JADX INFO: Fake field, exist only in values array */
    a EF0;

    static {
        a aVar = new a("CONSENT", 0);
        a aVar2 = new a("CONTRACT", 1);
        a = aVar2;
        b = new a[]{aVar, aVar2, new a("LEGAL_OBLIGATION", 2), new a("VITAL_INTERESTS", 3), new a("PUBLIC_TASK", 4), new a("LEGITIMATE_INTERESTS", 5)};
    }

    public static a valueOf(String str) {
        return (a) Enum.valueOf(a.class, str);
    }

    public static a[] values() {
        return (a[]) b.clone();
    }
}

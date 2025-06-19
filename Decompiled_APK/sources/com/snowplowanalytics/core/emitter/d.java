package com.snowplowanalytics.core.emitter;

import kotlin.text.D;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class d {
    public static final d a;
    public static final /* synthetic */ d[] b;

    /* JADX INFO: Fake field, exist only in values array */
    d EF0;

    static {
        d dVar = new d("TLSv1_1", 0);
        d dVar2 = new d("TLSv1_2", 1);
        a = dVar2;
        b = new d[]{dVar, dVar2};
    }

    public static d valueOf(String str) {
        return (d) Enum.valueOf(d.class, str);
    }

    public static d[] values() {
        return (d[]) b.clone();
    }

    @Override // java.lang.Enum
    public final String toString() {
        return D.o(name(), "_", ".", false);
    }
}

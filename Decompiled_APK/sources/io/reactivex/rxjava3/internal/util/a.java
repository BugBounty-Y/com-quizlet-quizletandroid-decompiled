package io.reactivex.rxjava3.internal.util;

import io.reactivex.rxjava3.functions.h;
import io.reactivex.rxjava3.functions.j;
import java.util.ArrayList;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class a implements j, h {
    public static final a a;
    public static final /* synthetic */ a[] b;

    static {
        a aVar = new a("INSTANCE", 0);
        a = aVar;
        b = new a[]{aVar};
    }

    public static a valueOf(String str) {
        return (a) Enum.valueOf(a.class, str);
    }

    public static a[] values() {
        return (a[]) b.clone();
    }

    @Override // io.reactivex.rxjava3.functions.h
    public final Object apply(Object obj) {
        return new ArrayList();
    }

    @Override // io.reactivex.rxjava3.functions.j
    public final Object get() {
        return new ArrayList();
    }
}

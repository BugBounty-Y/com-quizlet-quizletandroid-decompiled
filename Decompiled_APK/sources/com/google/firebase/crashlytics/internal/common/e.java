package com.google.firebase.crashlytics.internal.common;

import java.util.HashMap;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes2.dex */
public final class e {
    public static final e a;
    public static final HashMap b;
    public static final /* synthetic */ e[] c;

    /* JADX INFO: Fake field, exist only in values array */
    e EF0;

    static {
        e eVar = new e("X86_32", 0);
        e eVar2 = new e("X86_64", 1);
        e eVar3 = new e("ARM_UNKNOWN", 2);
        e eVar4 = new e("PPC", 3);
        e eVar5 = new e("PPC64", 4);
        e eVar6 = new e("ARMV6", 5);
        e eVar7 = new e("ARMV7", 6);
        e eVar8 = new e("UNKNOWN", 7);
        a = eVar8;
        e eVar9 = new e("ARMV7S", 8);
        e eVar10 = new e("ARM64", 9);
        c = new e[]{eVar, eVar2, eVar3, eVar4, eVar5, eVar6, eVar7, eVar8, eVar9, eVar10};
        HashMap map = new HashMap(4);
        b = map;
        map.put("armeabi-v7a", eVar7);
        map.put("armeabi", eVar6);
        map.put("arm64-v8a", eVar10);
        map.put("x86", eVar);
    }

    public static e valueOf(String str) {
        return (e) Enum.valueOf(e.class, str);
    }

    public static e[] values() {
        return (e[]) c.clone();
    }
}

package com.braze.events.internal.dispatchmanager;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes.dex */
public final class b {
    public static final b a;
    public static final b b;
    public static final b c;
    public static final b d;
    public static final /* synthetic */ b[] e;

    static {
        b bVar = new b("ADD_PENDING_BRAZE_EVENT", 0);
        a = bVar;
        b bVar2 = new b("ADD_BRAZE_EVENTS", 1);
        b = bVar2;
        b bVar3 = new b("FLUSH_PENDING_BRAZE_EVENTS", 2);
        c = bVar3;
        b bVar4 = new b("ADD_REQUEST", 3);
        d = bVar4;
        b[] bVarArr = {bVar, bVar2, bVar3, bVar4};
        e = bVarArr;
        AbstractC3328d.f(bVarArr);
    }

    public b(String str, int i) {
    }

    public static b valueOf(String str) {
        return (b) Enum.valueOf(b.class, str);
    }

    public static b[] values() {
        return (b[]) e.clone();
    }
}

package com.braze.requests.framework;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes.dex */
public final class i {
    public static final i a;
    public static final i b;
    public static final i c;
    public static final i d;
    public static final i e;
    public static final /* synthetic */ i[] f;

    static {
        i iVar = new i("PENDING_START", 0);
        a = iVar;
        i iVar2 = new i("PENDING_RETRY", 1);
        b = iVar2;
        i iVar3 = new i("IN_FLIGHT", 2);
        c = iVar3;
        i iVar4 = new i("BATCHED", 3);
        d = iVar4;
        i iVar5 = new i("COMPLETE", 4);
        e = iVar5;
        i[] iVarArr = {iVar, iVar2, iVar3, iVar4, iVar5};
        f = iVarArr;
        AbstractC3328d.f(iVarArr);
    }

    public i(String str, int i) {
    }

    public static i valueOf(String str) {
        return (i) Enum.valueOf(i.class, str);
    }

    public static i[] values() {
        return (i[]) f.clone();
    }

    public final boolean a() {
        return this == a || this == b;
    }
}

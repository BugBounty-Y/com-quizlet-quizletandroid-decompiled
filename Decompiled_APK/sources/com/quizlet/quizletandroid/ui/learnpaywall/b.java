package com.quizlet.quizletandroid.ui.learnpaywall;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class b {
    public static final b c;
    public static final b d;
    public static final /* synthetic */ b[] e;
    public final String a;
    public final com.quizlet.features.infra.models.upgrade.a b;

    static {
        b bVar = new b("LEARN", 0, "android_iap_source_learn_metering_paywall", com.quizlet.features.infra.models.upgrade.a.p);
        c = bVar;
        b bVar2 = new b("TEST", 1, "android_iap_source_test_metering_paywall", com.quizlet.features.infra.models.upgrade.a.q);
        d = bVar2;
        b[] bVarArr = {bVar, bVar2};
        e = bVarArr;
        AbstractC3328d.f(bVarArr);
    }

    public b(String str, int i, String str2, com.quizlet.features.infra.models.upgrade.a aVar) {
        this.a = str2;
        this.b = aVar;
    }

    public static b valueOf(String str) {
        return (b) Enum.valueOf(b.class, str);
    }

    public static b[] values() {
        return (b[]) e.clone();
    }
}

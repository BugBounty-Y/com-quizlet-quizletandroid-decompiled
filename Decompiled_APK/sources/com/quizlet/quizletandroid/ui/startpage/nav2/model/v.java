package com.quizlet.quizletandroid.ui.startpage.nav2.model;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class v {
    public static final v a;
    public static final /* synthetic */ v[] b;

    static {
        v vVar = new v("DeepLink", 0);
        a = vVar;
        v[] vVarArr = {vVar, new v("Home", 1), new v("Profile", 2), new v("DelayedSignupUpsell", 3)};
        b = vVarArr;
        AbstractC3328d.f(vVarArr);
    }

    public static v valueOf(String str) {
        return (v) Enum.valueOf(v.class, str);
    }

    public static v[] values() {
        return (v[]) b.clone();
    }
}

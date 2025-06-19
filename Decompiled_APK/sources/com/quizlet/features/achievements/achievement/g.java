package com.quizlet.features.achievements.achievement;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import com.quizlet.quizletandroid.R;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes2.dex */
public final class g {
    public static final /* synthetic */ g[] d;
    public final int a;
    public final int b;
    public final int c;

    static {
        g[] gVarArr = {new g(0, R.attr.AssemblyMint100, R.attr.AssemblyMint200, R.raw.notification_confetti_mint, "MINT"), new g(1, R.attr.AssemblyLilac100, R.attr.AssemblyLilac200, R.raw.notification_confetti_lilac, "LILAC"), new g(2, R.attr.AssemblySky100, R.attr.AssemblySky200, R.raw.notification_confetti_skyblue, "SKY"), new g(3, R.attr.RefColorSherbert100, R.attr.AssemblySherbert200, R.raw.notification_confetti_sherbert, "SHERBERT")};
        d = gVarArr;
        AbstractC3328d.f(gVarArr);
    }

    public g(int i, int i2, int i3, int i4, String str) {
        this.a = i2;
        this.b = i3;
        this.c = i4;
    }

    public static g valueOf(String str) {
        return (g) Enum.valueOf(g.class, str);
    }

    public static g[] values() {
        return (g[]) d.clone();
    }
}

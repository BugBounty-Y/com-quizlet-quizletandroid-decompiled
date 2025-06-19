package com.quizlet.quizletandroid.ui.common.adapter.viewholder;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import com.quizlet.quizletandroid.R;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class a {
    public static final a f;
    public static final a g;
    public static final /* synthetic */ a[] h;
    public final int a;
    public final int b;
    public final int c;
    public final int d;
    public final int e;

    static {
        a aVar = new a(0, R.dimen.leaderboard_height, R.dimen.leaderboard_elevation, R.dimen.leaderboard_margin_horizontal, R.dimen.leaderboard_ranking_width, R.dimen.leaderboard_time_start_margin, "NORMAL");
        f = aVar;
        a aVar2 = new a(1, R.dimen.leaderboard_height_highlighted, R.dimen.leaderboard_elevation_highlighted, R.dimen.leaderboard_margin_horizontal_highlighted, R.dimen.leaderboard_ranking_width_highlighted, R.dimen.leaderboard_time_start_margin_highlighted, "HIGHLIGHTED");
        g = aVar2;
        a[] aVarArr = {aVar, aVar2};
        h = aVarArr;
        AbstractC3328d.f(aVarArr);
    }

    public a(int i, int i2, int i3, int i4, int i5, int i6, String str) {
        this.a = i2;
        this.b = i3;
        this.c = i4;
        this.d = i5;
        this.e = i6;
    }

    public static a valueOf(String str) {
        return (a) Enum.valueOf(a.class, str);
    }

    public static a[] values() {
        return (a[]) h.clone();
    }
}
